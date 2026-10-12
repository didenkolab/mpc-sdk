#include <jni.h>
#include <string>
#include <cstdlib>

// ==================== DKLS23 Rust FFI declarations ====================
extern "C" {
    // Error handling
    char* dkls23_get_last_error();
    void dkls23_free_string(char* s);

    // DKG Functions
    void* dkls23_dkg_init(uint8_t party_id, size_t n_parties, size_t threshold);
    void dkls23_dkg_free_state(void* state);
    char* dkls23_dkg_generate_msg1(void* state);
    char* dkls23_dkg_handle_msg1(void* state, const char* msgs_json);
    char* dkls23_dkg_handle_msg2(void* state, const char* msgs_json);
    char* dkls23_dkg_calculate_commitment_2(void* state);
    char* dkls23_dkg_handle_msg3(void* state, const char* msgs_json, const char* commitments_json);
    char* dkls23_dkg_handle_msg4(void* state, const char* msgs_json);

    // DSG (Signing) Functions
    void* dkls23_dsg_init(const char* keyshare_json, const char* derivation_path);
    void dkls23_dsg_free_state(void* state);
    char* dkls23_dsg_generate_msg1(void* state);
    char* dkls23_dsg_handle_msg1(void* state, const char* msgs_json);
    char* dkls23_dsg_handle_msg2(void* state, const char* msgs_json);
    char* dkls23_dsg_handle_msg3(void* state, const char* msgs_json);
    char* dkls23_create_partial_signature(const char* presig_json, const uint8_t* msg_hash);
    char* dkls23_combine_signatures(const char* partial_json, const char* msg4_list_json);

    // Key derivation (uses keyshare JSON, not raw pubkey)
    char* dkls23_derive_public_key(const char* keyshare_json, const char* path);
}

// ==================== FROST Rust FFI declarations ====================
extern "C" {
    // Error handling
    char* frost_get_last_error();
    void frost_free_string(char* s);

    // DKG Functions (3 rounds for FROST vs 4 for DKLS23)
    void* frost_dkg_init(uint16_t party_id, uint16_t participants, uint16_t threshold);
    void frost_dkg_free_state(void* state);
    char* frost_dkg_generate_msg1(void* state);
    char* frost_dkg_handle_msg1(void* state, const char* msgs_json);
    char* frost_dkg_handle_msg2(void* state, const char* msgs_json);
    char* frost_dkg_finalize(void* state);

    // Signing Functions (2 rounds for FROST)
    void* frost_signing_init(const char* keyshare_json, const uint8_t* message_hash, size_t message_len);
    void frost_signing_free_state(void* state);
    char* frost_signing_generate_msg1(void* state);
    char* frost_signing_handle_msg1(void* state, const char* msgs_json);
    char* frost_signing_generate_msg2(void* state);
    char* frost_signing_handle_msg2(void* state, const char* msgs_json);

    // Signature functions
    char* frost_create_partial_signature(const char* presig_json, const uint8_t* message_hash);
    char* frost_combine_signatures(const char* partial_sig_json, const char* msg_list_json);

    // Key derivation
    char* frost_derive_public_key(const char* keyshare_json, const char* derivation_path);
    char* frost_derive_keyshare(const char* keyshare_json, const char* derivation_path);

    // Verification
    char* frost_verify_signature(const char* public_key, const uint8_t* message, size_t message_len, const char* signature);
}

// Helper to get last error as Java string
static jstring getLastError(JNIEnv* env) {
    char* err = dkls23_get_last_error();
    if (err != nullptr) {
        jstring result = env->NewStringUTF(err);
        dkls23_free_string(err);
        return result;
    }
    return env->NewStringUTF("Unknown error");
}

// Helper to convert jstring to const char*
static const char* jstringToChar(JNIEnv* env, jstring str) {
    if (str == nullptr) return nullptr;
    return env->GetStringUTFChars(str, nullptr);
}

// Helper to release jstring
static void releaseJString(JNIEnv* env, jstring str, const char* chars) {
    if (str != nullptr && chars != nullptr) {
        env->ReleaseStringUTFChars(str, chars);
    }
}

// Throws IllegalStateException with the last Rust FFI error. The JVM ignores
// the returned null because an exception is pending.
static jstring throwLastError(JNIEnv* env, bool frost) {
    char* err = frost ? frost_get_last_error() : dkls23_get_last_error();
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    env->ThrowNew(cls, err != nullptr ? err : "Unknown MPC error");
    if (err != nullptr) {
        if (frost) frost_free_string(err); else dkls23_free_string(err);
    }
    return nullptr;
}

extern "C" {

// ==================== DKG Functions ====================

JNIEXPORT jlong JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgInit(
        JNIEnv* env, jobject thiz,
        jint party_id, jint n_parties, jint threshold) {
    void* state = dkls23_dkg_init(
            static_cast<uint8_t>(party_id),
            static_cast<size_t>(n_parties),
            static_cast<size_t>(threshold)
    );
    return reinterpret_cast<jlong>(state);
}

JNIEXPORT void JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgFree(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)env; (void)thiz; // suppress unused warnings
    if (state_ptr != 0) {
        dkls23_dkg_free_state(reinterpret_cast<void*>(state_ptr));
    }
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgGenerateMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    if (state_ptr == 0) return throwLastError(env, false);

    char* result = dkls23_dkg_generate_msg1(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgHandleMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = dkls23_dkg_handle_msg1(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgHandleMsg2(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = dkls23_dkg_handle_msg2(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgCalculateCommitment2(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    if (state_ptr == 0) return throwLastError(env, false);

    char* result = dkls23_dkg_calculate_commitment_2(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgHandleMsg3(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json, jstring commitments_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    const char* commitments = jstringToChar(env, commitments_json);
    char* result = dkls23_dkg_handle_msg3(reinterpret_cast<void*>(state_ptr), msgs, commitments);
    releaseJString(env, msgs_json, msgs);
    releaseJString(env, commitments_json, commitments);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dkgHandleMsg4(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = dkls23_dkg_handle_msg4(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

// ==================== DSG (Signing) Functions ====================

JNIEXPORT jlong JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dsgInit(
        JNIEnv* env, jobject thiz, jstring keyshare_json, jstring derivation_path) {
    const char* keyshare = jstringToChar(env, keyshare_json);
    const char* path = jstringToChar(env, derivation_path);

    void* state = dkls23_dsg_init(keyshare, path);

    releaseJString(env, keyshare_json, keyshare);
    releaseJString(env, derivation_path, path);

    return reinterpret_cast<jlong>(state);
}

JNIEXPORT void JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dsgFree(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)env; (void)thiz; // suppress unused warnings
    if (state_ptr != 0) {
        dkls23_dsg_free_state(reinterpret_cast<void*>(state_ptr));
    }
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dsgGenerateMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    if (state_ptr == 0) return throwLastError(env, false);

    char* result = dkls23_dsg_generate_msg1(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dsgHandleMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = dkls23_dsg_handle_msg1(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dsgHandleMsg2(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = dkls23_dsg_handle_msg2(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_dsgHandleMsg3(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    if (state_ptr == 0) return throwLastError(env, false);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = dkls23_dsg_handle_msg3(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_createPartialSignature(
        JNIEnv* env, jobject thiz, jstring presig_json, jbyteArray msg_hash) {
    (void)thiz;
    const char* presig = jstringToChar(env, presig_json);
    jbyte* hash_bytes = env->GetByteArrayElements(msg_hash, nullptr);

    // FFI expects exactly 32 bytes, no length parameter needed
    char* result = dkls23_create_partial_signature(
            presig,
            reinterpret_cast<const uint8_t*>(hash_bytes)
    );

    env->ReleaseByteArrayElements(msg_hash, hash_bytes, 0);
    releaseJString(env, presig_json, presig);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_combineSignatures(
        JNIEnv* env, jobject thiz, jstring partial_json, jstring msg4_list_json) {
    const char* partial = jstringToChar(env, partial_json);
    const char* msg4_list = jstringToChar(env, msg4_list_json);

    char* result = dkls23_combine_signatures(partial, msg4_list);

    releaseJString(env, partial_json, partial);
    releaseJString(env, msg4_list_json, msg4_list);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

// ==================== Key Derivation ====================

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_deriveChildPubkey(
        JNIEnv* env, jobject thiz, jstring keyshare_json, jstring path) {
    (void)thiz;
    const char* keyshare = jstringToChar(env, keyshare_json);
    const char* derivation_path = jstringToChar(env, path);

    // Note: dkls23_derive_public_key takes keyshare JSON, not raw pubkey
    char* result = dkls23_derive_public_key(keyshare, derivation_path);

    releaseJString(env, keyshare_json, keyshare);
    releaseJString(env, path, derivation_path);

    if (result == nullptr) return throwLastError(env, false);

    jstring jresult = env->NewStringUTF(result);
    dkls23_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_getLastError(JNIEnv* env, jobject thiz) {
    return getLastError(env);
}

// ==================== FROST DKG Functions ====================

// Helper to get FROST last error
static jstring getFrostLastError(JNIEnv* env) {
    char* err = frost_get_last_error();
    if (err != nullptr) {
        jstring result = env->NewStringUTF(err);
        frost_free_string(err);
        return result;
    }
    return env->NewStringUTF("Unknown FROST error");
}

JNIEXPORT jlong JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDkgInit(
        JNIEnv* env, jobject thiz,
        jint party_id, jint n_parties, jint threshold) {
    (void)env; (void)thiz;
    void* state = frost_dkg_init(
            static_cast<uint16_t>(party_id),
            static_cast<uint16_t>(n_parties),
            static_cast<uint16_t>(threshold)
    );
    return reinterpret_cast<jlong>(state);
}

JNIEXPORT void JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDkgFree(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)env; (void)thiz;
    if (state_ptr != 0) {
        frost_dkg_free_state(reinterpret_cast<void*>(state_ptr));
    }
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDkgGenerateMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    char* result = frost_dkg_generate_msg1(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDkgHandleMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = frost_dkg_handle_msg1(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDkgHandleMsg2(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = frost_dkg_handle_msg2(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDkgFinalize(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    char* result = frost_dkg_finalize(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

// ==================== FROST Signing Functions ====================

JNIEXPORT jlong JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostSigningInit(
        JNIEnv* env, jobject thiz, jstring keyshare_json, jbyteArray msg_hash) {
    (void)thiz;
    const char* keyshare = jstringToChar(env, keyshare_json);
    jbyte* hash_bytes = env->GetByteArrayElements(msg_hash, nullptr);
    jsize hash_len = env->GetArrayLength(msg_hash);

    void* state = frost_signing_init(keyshare, reinterpret_cast<const uint8_t*>(hash_bytes), static_cast<size_t>(hash_len));

    env->ReleaseByteArrayElements(msg_hash, hash_bytes, 0);
    releaseJString(env, keyshare_json, keyshare);

    return reinterpret_cast<jlong>(state);
}

JNIEXPORT void JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostSigningFree(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)env; (void)thiz;
    if (state_ptr != 0) {
        frost_signing_free_state(reinterpret_cast<void*>(state_ptr));
    }
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostSigningGenerateMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    char* result = frost_signing_generate_msg1(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostSigningHandleMsg1(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = frost_signing_handle_msg1(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostSigningGenerateMsg2(
        JNIEnv* env, jobject thiz, jlong state_ptr) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    char* result = frost_signing_generate_msg2(reinterpret_cast<void*>(state_ptr));
    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostSigningHandleMsg2(
        JNIEnv* env, jobject thiz, jlong state_ptr, jstring msgs_json) {
    (void)thiz;
    if (state_ptr == 0) return throwLastError(env, true);

    const char* msgs = jstringToChar(env, msgs_json);
    char* result = frost_signing_handle_msg2(reinterpret_cast<void*>(state_ptr), msgs);
    releaseJString(env, msgs_json, msgs);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostCreatePartialSignature(
        JNIEnv* env, jobject thiz, jstring presig_json, jbyteArray msg_hash) {
    (void)thiz;
    const char* presig = jstringToChar(env, presig_json);
    jbyte* hash_bytes = env->GetByteArrayElements(msg_hash, nullptr);

    char* result = frost_create_partial_signature(presig, reinterpret_cast<const uint8_t*>(hash_bytes));

    env->ReleaseByteArrayElements(msg_hash, hash_bytes, 0);
    releaseJString(env, presig_json, presig);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostCombineSignatures(
        JNIEnv* env, jobject thiz, jstring partial_json, jstring msg_list_json) {
    (void)thiz;
    const char* partial = jstringToChar(env, partial_json);
    const char* msg_list = jstringToChar(env, msg_list_json);

    char* result = frost_combine_signatures(partial, msg_list);

    releaseJString(env, partial_json, partial);
    releaseJString(env, msg_list_json, msg_list);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostDerivePublicKey(
        JNIEnv* env, jobject thiz, jstring keyshare_json, jstring path) {
    (void)thiz;
    const char* keyshare = jstringToChar(env, keyshare_json);
    const char* derivation_path = jstringToChar(env, path);

    char* result = frost_derive_public_key(keyshare, derivation_path);

    releaseJString(env, keyshare_json, keyshare);
    releaseJString(env, path, derivation_path);

    if (result == nullptr) return throwLastError(env, true);

    jstring jresult = env->NewStringUTF(result);
    frost_free_string(result);
    return jresult;
}

JNIEXPORT jboolean JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostVerifySignature(
        JNIEnv* env, jobject thiz, jstring public_key_hex, jbyteArray message, jstring signature_hex) {
    (void)thiz;
    const char* public_key = jstringToChar(env, public_key_hex);
    const char* signature = jstringToChar(env, signature_hex);
    jbyte* message_bytes = env->GetByteArrayElements(message, nullptr);
    jsize message_len = env->GetArrayLength(message);

    char* result = frost_verify_signature(
            public_key,
            reinterpret_cast<const uint8_t*>(message_bytes),
            static_cast<size_t>(message_len),
            signature
    );

    env->ReleaseByteArrayElements(message, message_bytes, JNI_ABORT);
    releaseJString(env, public_key_hex, public_key);
    releaseJString(env, signature_hex, signature);

    if (result == nullptr) {
        throwLastError(env, true);
        return JNI_FALSE;
    }
    bool valid = std::string(result) == "true";
    frost_free_string(result);
    return valid ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_didenkolab_mpcsdk_demo_NativeMpc_frostGetLastError(JNIEnv* env, jobject thiz) {
    (void)thiz;
    return getFrostLastError(env);
}

} // extern "C"
