#include "pch.h"
#include <cstdio>
#include <vector>
#include <conio.h>

#include "hyperhook.h"
#include "../lul/peb.h"

NTSTATUS custom_query_process_information_hook(HANDLE,
                                               PROCESSINFOCLASS,
                                               uint8_t* ProcessInformation, ULONG,
                                               PULONG)
{
	puts("!!! Hook triggered");

	auto* desired_string = L"C:\\Users\\mauri\\source\\repos\\lul\\x64\\Release\\lul.exe";

	auto* res = reinterpret_cast<UNICODE_STRING*>(ProcessInformation);
	res->Buffer = reinterpret_cast<wchar_t*>(res + 1);
	res->Length = wcslen(desired_string) * 2;
	res->MaximumLength = res->Length;

	memcpy(res->Buffer, desired_string, res->Length);

	return 0;
}

std::vector<uint8_t> get_jump_bytes(void* address)
{
	std::vector<uint8_t> bytes{
		0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, 0x1122334455667788
		0xff, 0xe0, // jmp rax
	};

	memcpy(bytes.data() + 2, &address, sizeof(address));

	return bytes;
}

void write_bytes_regularly(void* place, const std::vector<uint8_t>& bytes)
{
	DWORD old_protect{};
	VirtualProtect(place, bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect);

	memcpy(place, bytes.data(), bytes.size());

	VirtualProtect(place, bytes.size(), old_protect, &old_protect);
}

void write_bytes_with_hypervisor(void* place, const std::vector<uint8_t>& bytes)
{
	hyperhook_write(GetCurrentProcessId(), reinterpret_cast<uint64_t>(place), bytes.data(), bytes.size());
}

void insert_hook(uint64_t address, void* target, const bool using_hypervisor)
{
	auto* place = reinterpret_cast<void*>(address);
	const auto bytes = get_jump_bytes(target);

	if (using_hypervisor)
	{
		write_bytes_with_hypervisor(place, bytes);
	}
	else
	{
		write_bytes_regularly(place, bytes);
	}
}

void run()
{
	puts("");
	puts("Hook DLL loaded");
	puts("Use hypervisor for hooks? (y/n)");
	const auto use_hypervisor = _getch() == 'y';

	if(use_hypervisor)
	{
		puts("Using hypervisor...");
	}else
	{
		puts("Using regular hooks...");
	}

	insert_hook(0x14004FAE8, &custom_query_process_information_hook, use_hypervisor);

	puts("");
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		run();
	}

	return TRUE;
}
