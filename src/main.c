// btfree - PSP Go Bluetooth device-class unlock (VSH plugin)
// Continuation of btfree3 by JJS / yoti, updated to run on 6.61 ARK-4 / ARK-5.
//
// Two things:
//   1. UNLOCK: patch bluetooth_plugin_module's device-class filter so every
//      discovered device is listed (a PC, a TV, headphones, etc.), not just the
//      classes Sony's firmware allows. This is a couple of in-RAM instruction
//      patches -- no syscall needed. (Correct 66x offsets + cache flush.)
//   2. LOG: record each device you register (name, class, BD_ADDR) to
//      ef0:/btfree_log.txt.
//
// The logging uses the method proven during the AirPods investigation: hijack
// sceBSMan's "register device" function (NID 0x8AC2F7B8), which is already a
// syscall, via sctrlHENFindFunction + HIJACK_FUNCTION. This avoids the old
// broken approach (creating a brand-new syscall for a hook inside the user-mode
// UI module), which sceKernelQuerySystemCall / sctrlHENMakeSyscallStub cannot do
// on 6.61 ARK (they return -1 / 0), silently disabling logging.
//
// SCOPE: this only affects the device LIST / class filter and logging. It does
// NOT fix Bluetooth pairing error 0x802F0130 (that is Apple's CVE-2024-27867
// auth hardening on the AirPods side -- see the separate writeup).

#include <pspsdk.h>
#include <pspkernel.h>
#include <systemctrl.h>
#include <cfwmacros.h>
#include <psploadcore.h>
#include <string.h>
#include <stdio.h>

PSP_MODULE_INFO("btfree", 0x1000, 0, 0);

#define LOG_PATH  "ef0:/btfree_log.txt"
#define REG_NID   0x8AC2F7B8   // sceBSMan "register device"

STMOD_HANDLER previousStartModuleHandler = NULL;
int firmware = 0;
int gHookInstalled = 0;

// { class-filter call-site (unused now), li-t6-5, beq-v0-t6 }
u32 patchAddresses_620[] = { 0x000095A4, 0x000094A8, 0x000094D4 };
u32 patchAddresses_63x[] = { 0x00013E00, 0x00013D04, 0x00013D30 };
u32 patchAddresses_66x[] = { 0x00013E3C, 0x00013D40, 0x00013D6C };
u32* patchAddresses = NULL;

int (*orig_reg)(int, int, int, int) = NULL;

void logStr(const char* s)
{
	SceUID f = sceIoOpen(LOG_PATH, PSP_O_CREAT | PSP_O_WRONLY | PSP_O_APPEND, 0777);
	if (f >= 0) { sceIoWrite(f, s, strlen(s)); sceIoClose(f); }
}

// Hijacked sceBSMan register-device call. a0 -> 0x54-byte device struct:
//   +0x06 name (UTF-16), +0x48/49/4A class, +0x4C BD_ADDR (6 bytes).
int reg_hook(int a0, int a1, int a2, int a3)
{
	int k1 = pspSdkSetK1(0);

	if ((u32)a0 >= 0x08000000)
	{
		u8* d = (u8*)a0;
		char nm[48];
		int i;
		for (i = 0; i < 40 && d[0x06 + i * 2]; i++) nm[i] = d[0x06 + i * 2];
		nm[i] = 0;

		char line[224];
		sprintf(line,
		        "--------------------\n"
		        "name    : %s\n"
		        "class   : %02X %02X %02X\n"
		        "BD_ADDR : %02X:%02X:%02X:%02X:%02X:%02X\n\n",
		        nm, d[0x48], d[0x49], d[0x4A],
		        d[0x4C], d[0x4D], d[0x4E], d[0x4F], d[0x50], d[0x51]);
		logStr(line);
	}

	int ret = orig_reg(a0, a1, a2, a3);
	pspSdkSetK1(k1);
	return ret;
}

// Install the device-logging hook on sceBSMan's register function.
static void installLogHook(void)
{
	if (gHookInstalled) return;

	u32 rf = sctrlHENFindFunction("sceBSMan", "sceBSMan", REG_NID);
	char line[96];
	sprintf(line, "register fn = 0x%08X\n", rf);
	logStr(line);

	if (rf && _lw(rf) == 0x27BDFFF0)   // expected prologue: addiu sp,sp,-16
	{
		HIJACK_FUNCTION(rf, reg_hook, orig_reg);
		sceKernelDcacheWritebackInvalidateAll();
		sceKernelIcacheInvalidateAll();
		gHookInstalled = 1;
		logStr("device log hook installed.\n");
	}
	else
	{
		logStr("WARN: sceBSMan register fn not found; logging disabled.\n");
	}
}

int on_module_start(SceModule* mod)
{
	if (strcmp(mod->modname, "bluetooth_plugin_module") == 0)
	{
		logStr("Entering on_module_start\n");

		char line[64];
		sprintf(line, "text_addr = 0x%08X\n", (u32)mod->text_addr);
		logStr(line);

		// Class-filter bypass: force every device to be accepted. No syscall
		// needed -- just two instruction patches.
		_sw(0x240EFFFF, mod->text_addr + patchAddresses[1]); // li $t6, 0xFFFF
		_sw(0x144E0003, mod->text_addr + patchAddresses[2]); // beq -> bne $v0,$t6

		sceKernelDcacheWritebackInvalidateAll();
		sceKernelIcacheInvalidateAll();

		logStr("class filter unlocked.\n");
	}

	if (previousStartModuleHandler)
		return previousStartModuleHandler(mod);
	return 0;
}

int module_start(SceSize args, void* argp)
{
	firmware = sceKernelDevkitVersion();

	char line[80];
	sprintf(line, "\n########## btfree loaded, fw 0x%08lX ##########\n\n", (u32)firmware);
	logStr(line);

	switch (firmware)
	{
		case 0x06020010:
			patchAddresses = patchAddresses_620; break;
		case 0x06030110:
		case 0x06030510:
			patchAddresses = patchAddresses_63x; break;
		case 0x06060010:
		case 0x06060110:
			patchAddresses = patchAddresses_66x; break;
	}

	if (!patchAddresses)
	{
		logStr("This firmware is not supported.\n");
		return 0;
	}

	// sceBSMan is a boot kernel module; install the log hook now (with a
	// start-module fallback in case it is not up yet).
	installLogHook();
	previousStartModuleHandler = sctrlHENSetStartModuleHandler(on_module_start);

	return 0;
}

int module_stop(SceSize args, void* argp)
{
	if (previousStartModuleHandler)
		sctrlHENSetStartModuleHandler(previousStartModuleHandler);
	return 0;
}
