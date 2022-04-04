package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.util.Map;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

public class FlutterSecureStoragePlugin implements MethodCallHandler {

    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureStorage";
    private SharedPreferences preferences;

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                preferences = initializeEncryptedSharedPreferencesManager(context);
            } catch (Exception e) {
                Log.e("FlutterSecureStoragePl", "EncryptedSharedPreferences initialization failed", e);
            }
        } else {
            preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        }
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

                    String value = (String) arguments.get("value");

                    if (value != null) {
                        write(key, value);
                        result.success(null);
                    } else {
                        result.error("null", null, null);
                    }
                    break;
                }
                case "read": {
                    String key = getKeyFromCall(call);

                    if (preferences.contains(key)) {
                        String value = read(key);
                        result.success(value);
                    } else {
                        result.success(null);
                    }
                    break;
                }
                case "readAll": {

                    Map<String, String> value = readAll();
                    result.success(value);
                    break;
                }
                case "containsKey": {
                    String key = getKeyFromCall(call);

                    boolean containsKey = preferences.contains(key);
                    result.success(containsKey);
                    break;
                }
                case "delete": {
                    String key = getKeyFromCall(call);

                    delete(key);
                    result.success(null);
                    break;
                }
                case "deleteAll": {
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
        return (String) arguments.get("key");
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> readAll() {
        return (Map<String, String>) preferences.getAll();
    }

    private void deleteAll() {
        preferences.edit().clear().commit();
    }

    private void write(String key, String value) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(key, value);
        editor.commit();
    }

    private String read(String key) {
        return preferences.getString(key, null);
    }

    private void delete(String key) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(key);
        editor.commit();
    }
}