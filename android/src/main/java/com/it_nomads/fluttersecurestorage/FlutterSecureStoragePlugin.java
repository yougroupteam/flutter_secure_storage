package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher18Implementation;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

public class FlutterSecureStoragePlugin implements MethodCallHandler {

    private static final String TAG = "FlutterSecureStoragePl";
    private static final String ELEMENT_PREFERENCES_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureStorage";
    private SharedPreferences preferences;
    private final SharedPreferences nonEncryptedPreferences;
    private final Charset charset;
    private StorageCipher storageCipher;
    private final Context applicationContext;
    private boolean useEncryptedSharedPreferences = false;

    public static void registerWith(Registrar registrar) {
        try {
            FlutterSecureStoragePlugin plugin = new FlutterSecureStoragePlugin(registrar.context());
            final MethodChannel channel = new MethodChannel(registrar.messenger(), "plugins.it_nomads.com/flutter_secure_storage");
            channel.setMethodCallHandler(plugin);
        } catch (Exception e) {
            Log.e("FlutterSecureStoragePl", "Registration failed", e);
        }
    }

    private FlutterSecureStoragePlugin(Context context) {
        applicationContext = context.getApplicationContext();
        nonEncryptedPreferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        charset = StandardCharsets.UTF_8;
    }

    private void checkAndMigrateToEncrypted(SharedPreferences source, SharedPreferences target) {
        for (Map.Entry<String, ?> entry : source.getAll().entrySet()) {
            Object v = entry.getValue();
            String key = entry.getKey();
            if (v instanceof String && key.contains(ELEMENT_PREFERENCES_KEY_PREFIX))
                try {
                    final String decodedValue = decodeRawValue((String) v);
                    target.edit().putString(key, (decodedValue)).commit();
                    source.edit().remove(key).commit();
                } catch (Exception e) {
                    Log.e(TAG, "Data migration failed", e);
                }
        }
    }

    private void ensureInitialized() {
        useEncryptedSharedPreferences = useEncryptedSharedPreferences();

        if (storageCipher == null) {
            try {
                storageCipher = new StorageCipher18Implementation(applicationContext);
            } catch (Exception e) {
                Log.e(TAG, "StorageCipher initialization failed", e);
            }
        }

        if (useEncryptedSharedPreferences &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

            try {
                preferences = initializeEncryptedSharedPreferencesManager(applicationContext);
            } catch (Exception e) {
                Log.e("FlutterSecureStoragePl", "EncryptedSharedPreferences initialization failed", e);
            }

            checkAndMigrateToEncrypted(nonEncryptedPreferences, preferences);
        } else {
            preferences = nonEncryptedPreferences;
        }
    }

    private boolean useEncryptedSharedPreferences() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private SharedPreferences initializeEncryptedSharedPreferencesManager(Context context) throws GeneralSecurityException, IOException {
        MasterKey key = new MasterKey.Builder(context)
                .setKeyGenParameterSpec(
                        new KeyGenParameterSpec
                                .Builder(MasterKey.DEFAULT_MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setKeySize(256).build())
                .build();
        return EncryptedSharedPreferences.create(context, SHARED_PREFERENCES_NAME, key, EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        try {
            switch (call.method) {
                case "write": {
                    String key = getKeyFromCall(call);
                    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
                    ensureInitialized();

                    String value = (String) arguments.get("value");

                    if (value != null) {
                        write(key, value, useEncryptedSharedPreferences);
                        result.success(null);
                    } else {
                        result.error("null", null, null);
                    }
                    break;
                }
                case "read": {
                    String key = getKeyFromCall(call);
                    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
                    ensureInitialized();

                    if (preferences.contains(key)) {
                        String value = read(key, useEncryptedSharedPreferences);
                        result.success(value);
                    } else {
                        result.success(null);
                    }
                    break;
                }
                case "readAll": {
                    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
                    ensureInitialized();

                    Map<String, String> value = readAll(useEncryptedSharedPreferences);
                    result.success(value);
                    break;
                }
                case "containsKey": {
                    String key = getKeyFromCall(call);
                    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
                    ensureInitialized();

                    boolean containsKey = preferences.contains(key);
                    result.success(containsKey);
                    break;
                }
                case "delete": {
                    String key = getKeyFromCall(call);
                    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
                    ensureInitialized();

                    delete(key);
                    result.success(null);
                    break;
                }
                case "deleteAll": {
                    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
                    ensureInitialized();

                    deleteAll();
                    result.success(null);
                    break;
                }
                default:
                    result.notImplemented();
                    break;
            }

        } catch (Exception e) {
            StringWriter stringWriter = new StringWriter();
            e.printStackTrace(new PrintWriter(stringWriter));
            result.error("Exception encountered", call.method, stringWriter.toString());
        }
    }

    @SuppressWarnings("unchecked")
    private String getKeyFromCall(MethodCall call) {
        Map<String, Object> arguments = (Map<String, Object>) call.arguments;
        String rawKey = (String) arguments.get("key");
        return addPrefixToKey(rawKey);
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> readAll(boolean useEncryptedSharedPreference) throws Exception {
        Map<String, String> raw = (Map<String, String>) preferences.getAll();

        Map<String, String> all = new HashMap<>();
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String keyWithPrefix = entry.getKey();
            if (keyWithPrefix.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                String key = entry.getKey().replaceFirst(ELEMENT_PREFERENCES_KEY_PREFIX + '_', "");
                if (useEncryptedSharedPreference) {
                    all.put(key, entry.getValue());
                } else {
                    String rawValue = entry.getValue();
                    String value = decodeRawValue(rawValue);

                    all.put(key, value);
                }
            }
        }
        return all;
    }

    private void deleteAll() {
        preferences.edit().clear().commit();
    }

    private void write(String key, String value, boolean useEncryptedSharedPreference) throws Exception {
        SharedPreferences.Editor editor = preferences.edit();

        if (useEncryptedSharedPreference) {
            editor.putString(key, value);
        } else {
            byte[] result = storageCipher.encrypt(value.getBytes(charset));
            editor.putString(key, Base64.encodeToString(result, 0));
        }
        editor.commit();
    }

    private String read(String key, boolean useEncryptedSharedPreference) throws Exception {
        String rawValue = preferences.getString(key, null);
        if (useEncryptedSharedPreference) {
            return rawValue;
        }
        return decodeRawValue(rawValue);
    }

    private void delete(String key) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(key);
        editor.commit();
    }

    private String addPrefixToKey(String key) {
        return ELEMENT_PREFERENCES_KEY_PREFIX + "_" + key;
    }

    private String decodeRawValue(String value) throws Exception {
        if (value == null) {
            return null;
        }
        byte[] data = Base64.decode(value, 0);
        byte[] result = storageCipher.decrypt(data);

        return new String(result, charset);
    }
}