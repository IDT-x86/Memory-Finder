#include "scanner.hpp"

Scanner::Scanner( std::vector<std::pair<std::string, std::string>>& signatures )
{
	m_signatures = signatures;
	m_signatureCount = 0;
	m_foundSignatures = { };
}

auto& Scanner::GetSignatures( ) const
{
	return m_signatures;
}

std::size_t Scanner::GetSignatureCount( ) const
{
	return m_signatureCount;
}

std::vector<std::tuple<std::string, std::string, std::uintptr_t, std::string>> Scanner::GetFoundSignatures( ) const
{
	return m_foundSignatures;
}

std::uintptr_t Scanner::FindPattern( const std::string& moduleName, const std::string& signature, int occurence )
{
	auto moduleHandle = GetModuleHandleA( moduleName.c_str() );

	if( !moduleHandle )
		return std::uintptr_t();

	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( moduleHandle );
	auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<std::uintptr_t>( moduleHandle ) + dosHeader->e_lfanew );

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto pattern = signature.c_str();

	auto endImage = reinterpret_cast<std::uintptr_t>( moduleHandle ) + sizeOfImage;
	auto s = pattern;

	std::uintptr_t currentMatch = 0;
	std::vector<std::uintptr_t> matches;

	for ( auto c = reinterpret_cast< std::uintptr_t >( moduleHandle ); c < endImage; c++ )
	{
		if ( !*s )
			return matches[ static_cast< size_t >( occurence ) - 1];

		if ( *( PBYTE )s == '\?' || *( BYTE* )c == getByte( s ) )
		{
			if ( !currentMatch )
				currentMatch = c;

			if ( !s[ 2 ] )
				matches.push_back( currentMatch );

			s += ( *( PWORD ) s == '\?\?' || *( PBYTE ) s != '\?' ) ? 3 : 2;
		}
		else
		{
			s = pattern;
			currentMatch = 0;
		}
	}

	if ( matches.size( ) >= occurence )
		return matches[ static_cast< size_t >( occurence ) - 1 ];

	return 0;
}


void Scanner::Scan( const std::string& moduleName )
{
	for ( auto& signature : m_signatures )
	{
		auto address = FindPattern( moduleName, signature.second );

		if ( address )
		{
			//std::cout << "Found " << signature.first << " at 0x" << std::hex << address << " in " << moduleName << std::endl;
			m_signatureCount++;
			m_foundSignatures.push_back( std::make_tuple( signature.first, signature.second, address, moduleName ) );
		}
		/*else
		{
			std::cout << "Failed to find " << signature.first << " in " << moduleName << std::endl;
		}*/
	}
}

void Scanner::Scan( const std::string& moduleName, const std::string& signatureName )
{
	for ( auto& signature : m_signatures )
	{
		if ( signature.first == signatureName )
		{
			auto address = FindPattern( moduleName, signature.second );

			if ( address )
			{
				//std::cout << "Found " << signature.first << " at 0x" << std::hex << address << " in " << moduleName << std::endl;
				m_signatureCount++;
				m_foundSignatures.push_back( std::make_tuple( signature.first, signature.second, address, moduleName ) );
			}
			/*else
			{
				std::cout << "Failed to find " << signature.first << " in " << moduleName << std::endl;
			}*/
		}
	}
}

void Scanner::ScanPattern( const std::string& moduleName, const std::string& signature, int occurence )
{
	auto address = FindPattern( moduleName, signature, occurence );

	if ( address )
	{
		//std::cout << "Found pattern at 0x" << std::hex << address << " in " << moduleName << std::endl;
		m_signatureCount++;
		m_foundSignatures.push_back( std::make_tuple( "[PatternScan]", signature, address, moduleName ) );
	}
	/*else
	{
		std::cout << "Failed to find pattern in " << moduleName << std::endl;
	}*/
}

void Scanner::ScanBytes( const std::string& moduleName, std::vector<uint8_t> detectionBytes )
{
	auto moduleHandle = GetModuleHandleA( moduleName.c_str( ) );

	if ( !moduleHandle )
		return;

	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( moduleHandle );
	auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<std::uintptr_t>( moduleHandle ) + dosHeader->e_lfanew );

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto pattern = detectionBytes.data();

	auto scanBytes = reinterpret_cast<std::uintptr_t>( moduleHandle );
	
	std::uintptr_t s = 0;

	while ( s < sizeOfImage )
	{
		if ( *reinterpret_cast< std::uint8_t* >( scanBytes + s ) == pattern[ 0 ] )
		{
			bool found = true;

			for ( std::size_t i = 1; i < detectionBytes.size( ); i++ )
			{
				if ( *reinterpret_cast< std::uint8_t* >( scanBytes + s + i ) != pattern[ i ] && pattern[ i ] != 0xCC )
				{
					found = false;
					break;
				}
			}

			if ( found )
			{
				//std::cout << "Found bytes at 0x" << std::hex << scanBytes + s << " in " << moduleName << std::endl;
				m_signatureCount++;

				std::string byteSequence = "";

				for ( auto& byte : detectionBytes )
				{
					char hexBuffer[ 3 ];
					sprintf_s( hexBuffer, "%.2X", byte );

					if ( &byte == &detectionBytes.back( ) )
					{
						byteSequence += hexBuffer;
					}
					else
					{
						byteSequence += hexBuffer;
						byteSequence += " ";
					}
				}

				//std::cout << signature << std::endl;

				m_foundSignatures.push_back( std::make_tuple( "[ByteScan]", byteSequence, scanBytes + s, moduleName ) );
			}
		}

		s++;
	}
}