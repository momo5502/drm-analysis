#define JM_XORSTR_DISABLE_AVX_INTRINSICS 1

#include <iostream>

#include "peb.h"
#include "xorstr.hpp"


#define LOAD_STR(x) (xorstr_(x))

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

// Adapt the hash in the compiled binary
volatile uint32_t theHash = 0x12345678;

// Adapt the value to the desired path
#define EXPECTED_FILENAME LOAD_STR("C:\\Users\\mauri\\source\\repos\\lul\\x64\\Release\\lul.exe")

extern "C" NTSTATUS __stdcall InlineNtQueryInformationProcess(HANDLE ProcessHandle,
                                                              PROCESSINFOCLASS ProcessInformationClass,
                                                              PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                              PULONG ReturnLength);

namespace
{
	FORCEINLINE bool str_equal(const char* s1, const char* s2)
	{
		for (size_t i = 0;; ++i)
		{
			if (s1[i] != s2[i])
			{
				return false;
			}

			if (s1[i] == 0)
			{
				break;
			}
		}

		return true;
	}

	FORCEINLINE uint32_t jenkins_one_at_a_time_hash(const uint8_t* key, const size_t length)
	{
		size_t i = 0;
		uint32_t hash = 0;
		while (i != length)
		{
			hash += key[i++];
			hash += hash << 10;
			hash ^= hash >> 6;
		}
		hash += hash << 3;
		hash ^= hash >> 11;
		hash += hash << 15;
		return hash;
	}

	FORCEINLINE std::pair<const uint8_t*, size_t> get_text_section()
	{
		auto* base = reinterpret_cast<uint8_t*>(&__ImageBase);
		auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + __ImageBase.e_lfanew);

		auto section = IMAGE_FIRST_SECTION(nt_headers);

		for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section)
		{
			if (str_equal(reinterpret_cast<const char*>(section->Name), ".text"))
			{
				return {base + section->VirtualAddress, section->Misc.VirtualSize};
			}
		}

		return {nullptr, 0};
	}

	FORCEINLINE uint32_t compute_text_hash()
	{
		const auto [addr, size] = get_text_section();
		return jenkins_one_at_a_time_hash(addr, size);
	}

	FORCEINLINE bool is_integrity_violated()
	{
		const auto computed = compute_text_hash();

		printf(LOAD_STR("Checksum: %08X\n"), computed);
		printf(LOAD_STR("Expected: %08X\n"), theHash);
		return computed != theHash;
	}

	FORCEINLINE void fill_module_filename(char* buffer, const size_t size)
	{
		if (size == 0) return;

		char totalBuffer[0x1024];
		auto* str = reinterpret_cast<UNICODE_STRING*>(totalBuffer);

		ULONG retLength{0};
		const auto res = InlineNtQueryInformationProcess(reinterpret_cast<HANDLE>(0xFFFFFFFFFFFFFFFF),
		                                                 ProcessImageFileNameWin32, &totalBuffer, sizeof(totalBuffer),
		                                                 &retLength);
		if (res != 0)
		{
			buffer[0] = 0;
			return;
		}

		size_t i = 0;
		for (; i < (str->Length / 2) && i < (size - 1); ++i)
		{
			buffer[i] = static_cast<char>(str->Buffer[i]);
		}

		buffer[i] = 0;
	}

	template <size_t Size>
	FORCEINLINE void fill_module_filename(char (&buffer)[Size])
	{
		fill_module_filename(buffer, Size);
	}

	FORCEINLINE bool was_copied()
	{
		char filename[MAX_PATH];
		fill_module_filename(filename);

		printf(LOAD_STR("Filename: %s\n"), filename);
		printf(LOAD_STR("Expected: %s\n"), EXPECTED_FILENAME);

		return !str_equal(filename, EXPECTED_FILENAME);
	}

	FORCEINLINE void stuff()
	{
		puts(LOAD_STR("Loading hook.dll..."));
		LoadLibraryA(LOAD_STR("hook.dll"));

		bool valid = true;

		puts("");

		if (is_integrity_violated())
		{
			puts(LOAD_STR(" -> Integrity violation!"));
			valid = false;
		}

		puts("");

		if (was_copied())
		{
			puts(LOAD_STR(" -> You copied the program"));
			valid = false;
		}

		puts("");

		if (!valid)
		{
			puts(LOAD_STR("Something's wrong."));
			return;
			
		}

		puts(LOAD_STR("Yay program is running!"));
	}

	// This essentially does nothing.
	// Its only purpose is to look confusing in IDA to simulate obfuscation.

	template <int Count>
	FORCEINLINE bool decisionMaker(volatile unsigned int* num)
	{
		if constexpr (Count == 0)
		{
			return *num == 3;
		}

		if constexpr (Count == 1)
		{
			return *num & 100;
		}

		if constexpr (Count > 2)
		{
			if (*num == 3)
			{
				*num ^= Count;
				return decisionMaker<Count>(num);
			}

			if constexpr (Count < 5)
			{
				if (*num > 40)
				{
					*num = ~Count;
					return decisionMaker<Count + 1>(num);
				}
			}


			if (Count % 4 && *num > 4)
			{
				constexpr auto newCount = Count >> 1;
				return decisionMaker<newCount>(num);
			}

			if (*num % Count == 0)
			{
				*num = (*num & ~3) ^ ~Count;
				return decisionMaker<Count - 1>(num);
			}

			++*num;

			return decisionMaker<Count - 2>(num) ^ decisionMaker<Count - 1>(num);
		}

		return true;
	}
}

int main(int argc)
{
	if (argc > 3 && decisionMaker<11>((volatile unsigned int*)&argc))
	{
		return 1;
	}

	stuff();

	if (argc > 4 && decisionMaker<7>((volatile unsigned int*)&argc))
	{
		return 1;
	}

	return 0;
}
