#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>

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

    sqlite3_bind_text(stmt, 1, value1.c_str(), -1, SQLITE_STATIC);
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

// Pull the EVP_PKEY value from a string
EVP_PKEY* convertFromPrivateKeyString(const std::string& privString){
    BIO* bio = BIO_new_mem_buf(privString.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
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

    std::string pub_key = extract_pub_key(pkey);
    std::string priv_key = extract_priv_key(pkey);

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

    auto now = std::chrono::system_clock::now();
    auto timeSinceEpoch = now.time_since_epoch();
    std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(timeSinceEpoch);
    int nowTime = static_cast<int>(sec.count());
    int hourTime = static_cast<int>(sec.count() + 3600);

    rc = insertData(priv_key, std::to_string(nowTime));
    if(rc != SQLITE_OK){
        std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
    }
    else{
        std::cout << "Record inserted successfully\n";
    }

    rc = insertData(priv_key, std::to_string(hourTime));
    if(rc != SQLITE_OK){
        std::cout << "SQL error: " << sqlite3_errmsg(db) << std::endl;
    }
    else{
        std::cout << "Record inserted successfully\n";
    }
        

    // Start HTTP server
    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res)
             {
        if (req.method != "POST") {
            res.status = 405;  // Method Not Allowed
            res.set_content("Method Not Allowed", "text/plain");
            return;
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
            std::cout << rc << std::endl;
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

        EVP_PKEY* pkey = convertFromPrivateKeyString(priv);
        std::string pub_key = extract_pub_key(pkey);
        std::string priv_key = extract_priv_key(pkey);

        sqlite3_finalize(stmt);

        std::cout << "JWT keyID: " << std::to_string(keyID) << std::endl;

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
            std::cout << rc << std::endl;
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
            EVP_PKEY* pkey = convertFromPrivateKeyString(priv);

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
