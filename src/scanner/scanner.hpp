#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <tuple>
#include <iostream>

#define inRange( x, a, b ) ( x >= a && x <= b )
#define getBits( x ) ( inRange( ( x & ( ~0x20 ) ), 'A', 'F' ) ? ( ( x & ( ~0x20 ) ) - 'A' + 0xA ) : ( inRange( x, '0', '9' ) ? x - '0' : 0 ) )
#define getByte( x ) ( getBits( x[ 0 ] ) << 4 | getBits( x[ 1 ] ) )

class Scanner
{
public:
	Scanner( ) = default;
	Scanner( std::vector<std::pair<std::string, std::string>>& signatures );

	auto& GetSignatures( ) const;
	std::vector<std::tuple<std::string, std::string, std::uintptr_t, std::string>> GetFoundSignatures( ) const;
	std::size_t GetSignatureCount( ) const;

	void Scan( const std::string& moduleName );
	void Scan( const std::string& moduleName, const std::string& signatureName );
	void ScanPattern( const std::string& moduleName, const std::string& signature, int occurence = 1 );
	void ScanBytes( const std::string& moduleName, std::vector<uint8_t> detectionBytes );

private:
	std::vector<std::pair<std::string, std::string>> m_signatures { };
	std::vector<std::tuple<std::string, std::string, std::uintptr_t, std::string>> m_foundSignatures { };
	std::size_t m_signatureCount { 0 };

	std::uintptr_t FindPattern( const std::string& moduleName, const std::string& signature, int occurence = 1 );
};