#include <iostream>
#include <string>
#include <chrono>
#include <mutex>
#include <thread>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <sqlite3.h>
#include <uuid/uuid.h>
#include <argon2.h>
#include <nlohmann/json.hpp>

#define HASHLEN 32
#define SALTLEN 16

using json = nlohmann::json;

class RateLimiter{
    public:
        RateLimiter(int rate, std::chrono::seconds window)
            : rate_(rate), window_(window), tokens_(0) {}
        
        bool allowRequest() {
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = std::chrono::steady_clock::now();
            auto elapsed_time = now - last_refill_time_;

            int tokens_to_add = static_cast<int>(elapsed_time / std::chrono::seconds(1) * rate_);
            tokens_ = std::min(tokens_ + tokens_to_add, rate_);

            last_refill_time_ = now;

            if(tokens_ > 0){
                tokens_--;
                return true;
            }

            return false;
        }
    private:
        int rate_;
        std::chrono::seconds window_;
        int tokens_;
        std::chrono::steady_clock::time_point last_refill_time_;
        std::mutex mutex_;
};

// Hashes Generated password using Argon2
std::string hashPassword(const std::string& password){
    uint8_t hash[HASHLEN];
    uint8_t salt[SALTLEN];
    memset(salt, 0x00, SALTLEN);
    
    uint8_t *pwd = (uint8_t *)strdup(password.c_str());
    uint32_t pwdlen = strlen((char *)pwd);

    uint32_t t_cost = 2;
    uint32_t m_cost = (1<<16);
    uint32_t parallelism = 1;

    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash, HASHLEN);

    if(hash){
        char* chash = (char*)hash;
        std::string finalHash = chash;
        return finalHash;
    } else {
        return "FUCK";
    }
}

std::string generatePassword(){
    uuid_t uuid;
    uuid_generate_random(uuid);

    char uuidStr[37];
    uuid_unparse(uuid, uuidStr);

    return std::string(uuidStr);
}

std::string bignum_to_raw_string(const BIGNUM *bn)
{
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

std::string extract_pub_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string extract_priv_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string base64_url_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++)
    {
        char_array_3[i++] = data[n];
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
    }

    // Replace '+' with '-', '/' with '_' and remove '='
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
}

// Create a callback function  
int callback(void *NotUsed, int argc, char **argv, char **azColName){

    // int argc: holds the number of results
    // (array) azColName: holds each column returned
    // (array) argv: holds each value

    for(int i = 0; i < argc; i++) {
        
        // Show column name, value, and newline
        std::cout << azColName[i] << ": " << argv[i] << std::endl;
    
    }

    // Insert a newline
    std::cout << std::endl;

    // Return successful
    return 0;
}

// Insert data into SQLite Database
int insertData(std::string value1, std::string value2){
    sqlite3* db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if(rc){
        fprintf(stderr, "Can't open database :%s\n", sqlite3_errmsg(db));
        return rc;
    }

    std::string query = "INSERT INTO keys (key, exp) VALUES (?, ?);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if(rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_bind_blob(stmt, 1, value1.c_str(), value1.length(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value2.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE){
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return SQLITE_OK;
}

int insertRegister(std::string value1, std::string value2, std::string value3, std::string value4){
    sqlite3* db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if(rc){
        fprintf(stderr, "Can't open database :%s\n", sqlite3_errmsg(db));
        return rc;
    }

    std::string query = "INSERT INTO users (username, password_hash, email, last_login) VALUES (?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if(rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_bind_text(stmt, 1, value1.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value2.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, value3.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, value4.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE){
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return SQLITE_OK;
}

int insertRequest(std::string value1, std::string value2, std::string value3){
    sqlite3* db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if(rc){
        fprintf(stderr, "Can't open database :%s\n", sqlite3_errmsg(db));
        return rc;
    }

    std::string query = "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if(rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_bind_text(stmt, 1, value1.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value2.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, value3.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE){
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return SQLITE_OK;
}

// Get the user ID from the given username
int get_userID(std::string username){
    sqlite3* db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if(rc){
        fprintf(stderr, "Can't open database :%s\n", sqlite3_errmsg(db));
        return rc;
    }

    std::string sqlQuery = "SELECT id FROM users WHERE username = ?;";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, nullptr);

    if(rc != SQLITE_OK)
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_bind_text(stmt, 4, username.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE){
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    int user_id = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return user_id;
}

// Pull the EVP_PKEY value from a string
EVP_PKEY* convertFromPrivateKeyString(const std::string& privString){
    BIO* bio = BIO_new_mem_buf(privString.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// AES Encryption
std::string aes_encrypt(const std::string &plaintext, const std::string &key){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // Initialize IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);

    // Initialize encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv);

    // Encrypt
    int ciphertext_len = plaintext.length() + EVP_MAX_BLOCK_LENGTH;
    unsigned char ciphertext[ciphertext_len];
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    int final_len; 
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    std::string result(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH);
    result += std::string(reinterpret_cast<char*>(ciphertext), ciphertext_len);

    return result;
}

// AES Decryption
std::string aes_decrypt(const std::string &ciphertext, const std::string &key){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Extract IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    std::memcpy(iv, ciphertext.c_str(), EVP_MAX_IV_LENGTH);

    // Initialize decryption
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv);

    // Decrypt
    int plaintext_len = ciphertext.length() - EVP_MAX_IV_LENGTH;
    unsigned char plaintext[plaintext_len];
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()) + EVP_MAX_IV_LENGTH, plaintext_len);
    int final_len;
    EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len);
    plaintext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext), plaintext_len);
}

struct KeyData{
    int kid; 
    std::vector<unsigned char> key;
    int exp;
};

int main()
{
    // Generate RSA key pair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Keys
    std::string pub_key_master = extract_pub_key(pkey);
    std::string priv_key = extract_priv_key(pkey);

    // Get key from environment variable
    if(!std::getenv("NOT_MY_KEY")){
        std::cerr << "NOT_MY_KEY not set\n";
        return 1;
    }

    // Create SQLite Database
    sqlite3 *db;
    std::string sql;
    std::string sqlQuery;
    char *zErrMsg = 0;
    int rc;

    rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
    if(rc){
        fprintf(stderr, "Can't open database :%s\n", sqlite3_errmsg(db));
        return(0);
    } else {
        fprintf(stderr, "Opened database successfully\n");
    }

    // Schema
    sql = "CREATE TABLE IF NOT EXISTS keys(" \
        "kid INTEGER PRIMARY KEY AUTOINCREMENT," \
        "key BLOB NOT NULL," \
        "exp INTEGER NOT NULL);";
    
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);

    sql = "CREATE TABLE IF NOT EXISTS users(" \
        "id INTEGER PRIMARY KEY AUTOINCREMENT," \
        "username TEXT NOT NULL UNIQUE," \
        "password_hash TEXT NOT NULL," \
        "email TEXT UNIQUE," \
        "date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP," \
        "last_login TIMESTAMP);";
    
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);

    sql = "CREATE TABLE IF NOT EXISTS auth_logs(" \
        "id INTEGER PRIMARY KEY AUTOINCREMENT," \
        "request_ip TEXT NOT NULL," \
        "request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP," \
        "user_id INTEGER," \
        "FOREIGN KEY(user_id) REFERENCES users(id));";

    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);

    if(rc != SQLITE_OK){
        std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
    }

    auto now = std::chrono::system_clock::now();
    auto timeSinceEpoch = now.time_since_epoch();
    std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(timeSinceEpoch);
    int nowTime = static_cast<int>(sec.count());
    int hourTime = static_cast<int>(sec.count() + 3600);

    std::string encrypted_priv_key = aes_encrypt(priv_key, std::getenv("NOT_MY_KEY"));

    rc = insertData(encrypted_priv_key, std::to_string(nowTime));
    if(rc != SQLITE_OK){
        std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
    }
    else{
        std::cout << "Record inserted successfully: Invalid Key\n";
    }

    rc = insertData(encrypted_priv_key, std::to_string(hourTime));
    if(rc != SQLITE_OK){
        std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
    }
    else{
        std::cout << "Record inserted successfully: Valid Key\n";
    }
        

    // Start HTTP server
    httplib::Server svr;

    RateLimiter rateLimiter(10, std::chrono::seconds(1));

    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res)
             {
        if (req.method != "POST") {
            res.status = 405;  // Method Not Allowed
            res.set_content("Method Not Allowed", "text/plain");
            return;
        }
        
        if(!rateLimiter.allowRequest()){
            res.status = 429;
            res.set_content("Too Many Requests", "text/plain");
            return;
        }

        json incoming_json = json::parse(req.body);

        std::string username = incoming_json["username"];
        int user_id = get_userID(username);
        std::string request_ip = req.get_header_value("REMOTE_ADDR");

        auto currentTime = std::chrono::system_clock::now();
        std::time_t currentTime_t = std::chrono::system_clock::to_time_t(currentTime);
        std::tm tmStruct = *std::localtime(&currentTime_t);
        std::ostringstream timeStr;
        timeStr << std::put_time(&tmStruct, "%Y-%m-%d %H:%M:%S");
        auto duration = currentTime.time_since_epoch();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
        std::ostringstream millisStr; 
        millisStr << std::setfill('0') << std::setw(3) << milliseconds;

        std::string request_timestamp = timeStr.str() + "." + millisStr.str();


        rc = insertRequest(request_ip, request_timestamp, std::to_string(user_id));
        if(rc != SQLITE_OK){
            std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        }
        else{
            std::cout << "Record inserted successfully: auth_logs\t";
            std::cout << request_timestamp << std::endl;
        }

        // Check if the "expired" query parameter is set to "true"
        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
        
        // Get current time (set to function maybe)
        auto now = std::chrono::system_clock::now();
        auto timeSinceEpoch = now.time_since_epoch();
        std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(timeSinceEpoch);
        int nowTime = static_cast<int>(sec.count());

        if(expired){
            sqlQuery = "SELECT * FROM keys WHERE exp < ?;";
        }else{
            sqlQuery = "SELECT * FROM keys WHERE exp >= ?;";
        }

        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, nullptr);
        if(rc != SQLITE_OK){
            std::cerr << "Error in preparing SQL statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return;
        }

        sqlite3_bind_text(stmt, 1, std::to_string(nowTime).c_str(), -1, SQLITE_STATIC);

        std::vector<KeyData> results;   

        // Pull data from valid row, take first value
        while((rc = sqlite3_step(stmt)) == SQLITE_ROW){
            KeyData data;
            //std::cout << rc << std::endl;
            data.kid = sqlite3_column_int(stmt, 0);
            //std::cout << "\tWhile loop: " << std::to_string(keyID) << std::endl;
            const unsigned char* keyPtr = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 1));
            int keySize = sqlite3_column_bytes(stmt, 1);
            data.key.assign(keyPtr, keyPtr + keySize);
            data.exp = sqlite3_column_int(stmt, 2);
            results.push_back(data);
        }

        KeyData firstResult = results[0];

        std::vector<unsigned char> keyVector = firstResult.key;
        std::string priv(keyVector.begin(), keyVector.end());
        int keyID = firstResult.kid;
        int exp = firstResult.exp;
        
        // Convert exp value into usable value
        std::chrono::system_clock::time_point tp = std::chrono::system_clock::from_time_t(exp);
        jwt::date expDate(tp);

        std::string decrypted_priv = aes_decrypt(priv, std::getenv("NOT_MY_KEY"));

        EVP_PKEY* pkey = convertFromPrivateKeyString(decrypted_priv);
        std::string pub_key = extract_pub_key(pkey);
        std::string priv_key = extract_priv_key(pkey); 

        sqlite3_finalize(stmt);

        // Create JWT token
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_payload_claim("sample", jwt::claim(std::string("test")))
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(expDate)
            .set_key_id(std::to_string(keyID))
            .sign(jwt::algorithm::rs256(pub_key, priv_key));

        res.set_content(token, "text/plain"); });

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request &, httplib::Response &res)
            {
        sqlQuery = "SELECT * FROM keys WHERE exp >= ?;";

        // Get Current Time (Maybe Set to Fuction Call)
        auto now = std::chrono::system_clock::now();
        auto timeSinceEpoch = now.time_since_epoch();
        std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(timeSinceEpoch);
        int nowTime = static_cast<int>(sec.count());

        // Send the Query
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, nullptr);
        if(rc != SQLITE_OK){
            std::cerr << "Error in preparing SQL statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return;
        }

        sqlite3_bind_text(stmt, 1, std::to_string(nowTime).c_str(), -1, SQLITE_STATIC);

        std::string jwks = "{ \"keys\": [\n";
        
        // Loop through all selected rows 
        std::vector<KeyData> results;   

        // Pull data from valid row, take first value
        while((rc = sqlite3_step(stmt)) == SQLITE_ROW){
            KeyData data;
            //std::cout << rc << std::endl;
            data.kid = sqlite3_column_int(stmt, 0);
            //std::cout << "\tWhile loop: " << std::to_string(keyID) << std::endl;
            const unsigned char* keyPtr = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 1));
            int keySize = sqlite3_column_bytes(stmt, 1);
            data.key.assign(keyPtr, keyPtr + keySize);
            data.exp = sqlite3_column_int(stmt, 2);
            results.push_back(data);
        }

        int resultsSize = static_cast<int>(results.size());
        for(int i = 0; i < resultsSize; i++){
            KeyData firstResult = results[i];

            std::vector<unsigned char> keyVector = firstResult.key;
            std::string priv(keyVector.begin(), keyVector.end());
            int keyID = firstResult.kid;
            int exp = firstResult.exp;

            // Convert to Private Key
            std::string decrypted_priv = aes_decrypt(priv, std::getenv("NOT_MY_KEY"));
            EVP_PKEY* pkey = convertFromPrivateKeyString(decrypted_priv);

            BIGNUM* n = NULL;
            BIGNUM* e = NULL;

            // Pull Exponent and Modulus
            if (!EVP_PKEY_get_bn_param(pkey, "n", &n) || !EVP_PKEY_get_bn_param(pkey, "e", &e)) {
                res.set_content("Error retrieving JWKS", "text/plain");
                return;
            }

            std::string n_encoded = base64_url_encode(bignum_to_raw_string(n));
            std::string e_encoded = base64_url_encode(bignum_to_raw_string(e));

            BN_free(n);
            BN_free(e);

            // Add JWK to JWKS
            jwks += "\n\t\t{\n\t\t\t\"alg\": \"RS256\", \n\t\t\t\"kty\": \"RSA\", \n\t\t\t\"use\": \"sig\", \n\t\t\t\"kid\": \"" + std::to_string(keyID) + "\", \n\t\t\t\"n\": \"" + n_encoded + "\", \n\t\t\t\"e\": \"" + e_encoded + "\"\n\t\t}";

            if(i < (resultsSize - 1))
                jwks += ",\n";
        }
        jwks += "\n\t]\n}";
        std::cout << jwks << std::endl;
        sqlite3_finalize(stmt);
        res.set_content(jwks, "application/json"); });

    svr.Post("/register", [&](const httplib::Request &req, httplib::Response &res)
    {
        json incoming_json = json::parse(req.body);

        std::string username = incoming_json["username"];
        std::string email = incoming_json["email"];
        
        std::string newPassword = generatePassword();
        std::string hashedPass = hashPassword(newPassword);

        auto currentTime = std::chrono::system_clock::now();
        std::time_t currentTime_t = std::chrono::system_clock::to_time_t(currentTime);
        std::tm tmStruct = *std::localtime(&currentTime_t);
        std::ostringstream timeStr;
        timeStr << std::put_time(&tmStruct, "%Y-%m-%d %H:%M:%S");
        auto duration = currentTime.time_since_epoch();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
        std::ostringstream millisStr; 
        millisStr << std::setfill('0') << std::setw(3) << milliseconds;

        std::string lastLogin = timeStr.str() + "." + millisStr.str();
        

        rc = insertRegister(username, hashedPass, email, lastLogin);
        if(rc != SQLITE_OK){
            std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        }
        else{
            std::cout << "Record inserted successfully: Register\t";
            std::cout << lastLogin << std::endl;
        }

        std::string jsonString = "{\"password\": \"" + newPassword + "\"}";

        res.set_content(jsonString, "application/json"); });

    // Catch-all handlers for other methods
    auto methodNotAllowedHandler = [](const httplib::Request &req, httplib::Response &res)
    {
        if (req.path == "/auth" || req.path == "/.well-known/jwks.json")
        {
            res.status = 405;
            res.set_content("Method Not Allowed", "text/plain");
        }
        else
        {
            res.status = 404;
            res.set_content("Not Found", "text/plain");
        }
    };

    svr.Get(".*", methodNotAllowedHandler);
    svr.Post(".*", methodNotAllowedHandler);
    svr.Put(".*", methodNotAllowedHandler);
    svr.Delete(".*", methodNotAllowedHandler);
    svr.Patch(".*", methodNotAllowedHandler);

    svr.listen("127.0.0.1", 8080);

    // Cleanup
    EVP_PKEY_free(pkey);
    sqlite3_close(db);

    return 0;
}