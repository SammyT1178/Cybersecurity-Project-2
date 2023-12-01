# Variables
CXX = g++
CXXFLAGS = -std=c++11 -I./httplib -I./jwt-cpp/include -I./argon2/include -I./nlohmann/include -L./argon2
LDFLAGS = -lcrypto -lssl -lsqlite3 -luuid -largon2
TARGET = jwks_server
SOURCES = main.cpp

# Get the path to the OpenSSL installation from Homebrew
OPENSSL_PREFIX := $(shell brew --prefix openssl)
SQLITE_PREFIX := $(shell brew --prefix sqlite3)

# Add the path to the OpenSSL headers to the CXXFLAGS variable
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib

# Default target
all: fetch $(TARGET)

# Target to build the program
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

# Target to fetch the required libraries
fetch:
	# Check if httplib directory exists, if not fetch it
	@if [ ! -d "httplib" ]; then \
		git clone https://github.com/yhirose/cpp-httplib.git httplib; \
	fi

	# Check if jwt-cpp directory exists, if not fetch it
	@if [ ! -d "jwt-cpp" ]; then \
		git clone https://github.com/Thalhammer/jwt-cpp.git; \
	fi

	# Check if argon2 directory exists, if not fetch it
	@if [ ! -d "argon2" ]; then \
		git clone https://github.com/P-H-C/phc-winner-argon2.git argon2; \
		cd argon2; make; cd ..; \
	fi

	# Check if nlohmann/json directory exists, if not fetch it
	@if [ ! -d "nlohmann" ]; then \
		git clone https://github.com/nlohmann/json.git nlohmann; \
	fi

clean:
	rm -rf $(TARGET) httplib jwt-cpp nlohmann argon2 totally_not_my_privateKeys.db

.PHONY: all fetch clean
