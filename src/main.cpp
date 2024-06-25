#include <iostream>
#include <intrin.h>
#include "scanner/scanner.hpp"
#include "spoofer.hpp"

#pragma section (".text") // allocates a "jmp qword ptr [rbx]" within the .text section of our EXE
__declspec( allocate( ".text" ) ) // jmp qword ptr rbx
uint8_t jmp_shellcode[ ] = { 0xFF, 0xE0 };

auto test( ) -> void
{
    std::cout << "Called from Return Address: 0x" << std::hex << _ReturnAddress( ) << std::endl;
}

std::vector<std::pair<std::string, std::string>> detectedSignatures = {
    std::make_pair( "TableEntry", "48 83 EC ? 48 83 64 24 20 00 41 B9 ? ? ? ? 4C 8D" ),
    std::make_pair( "JmpShellcode", "FF 27" ),
    std::make_pair( "VirtualAlloc", "40 53 48 83 EC ? 33 DB 48 89" )
};

int main()
{
    auto scannerInstance = std::make_unique<Scanner>( detectedSignatures );

    std::vector<uint8_t> toScan = { 0xFF, 0x27 };

    scannerInstance->Scan( "ntdll.dll" );

    scannerInstance->ScanBytes( "ntdll.dll", toScan );

    auto& jmpShellcode = scannerInstance->GetFoundSignatures( )[ scannerInstance->GetSignatureCount( ) - 1 ];

    std::cout << "Detected " << scannerInstance->GetSignatureCount( ) << " signatures" << std::endl;
 
    for ( auto& signature : scannerInstance->GetFoundSignatures( ) )
    {
        std::cout << "Found detection " << std::get<0>( signature ) << " at 0x" << std::hex << std::get<2>( signature ) << " with " << std::get<1>( signature ) << " in module " << std::get<3>( signature ) << std::endl;
	};


    return std::cin.get( );
}
