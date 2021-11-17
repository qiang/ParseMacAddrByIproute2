package com.github.propparser;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        int permissionCheck = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE);

        if (permissionCheck != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.READ_PHONE_STATE}, 111111);
        } else {
            //TODO
        }
    }

    public native void parsePropFile();

    public native void parsePropInMemroy();

    public native void getPropByApi();

    public void click(View view) {

        try {
            //BufferedReader是可以按行读取文件
            FileInputStream inputStream = new FileInputStream("/proc/self/maps");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
            String str = null;
//            700130c000-7001311000 r--p 00286000 fc:04 2093                           /system/framework/arm64/boot.art
            while ((str = bufferedReader.readLine()) != null) {
                if (str.contains("/dev/__properties__/u:object_r:vendor_default_prop:s0")) {
                    Log.d("Q_M", str);
                    String memoryAddr = str.substring(0, str.indexOf(" "));
                    String[] beginAndEnd = memoryAddr.split("-");
                    Log.d("Q_M", Arrays.toString(beginAndEnd));

                    parsePropFile();
                }
            }

            //close
            inputStream.close();
            bufferedReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

//        parseProp();
    }

    public void getSerialByNativeApi(View view) {
        getPropByApi();
    }

//    Android 10及以上：分为以下两种情况：
//    targetSdkVersion<29：没有申请权限的情况，调用Build.getSerial()方法时抛出java.lang.SecurityException异常；申请了权限，通过Build.getSerial()方法获取到的设备序列号为“unknown”
//    targetSdkVersion=29：无论是否申请了权限，调用Build.getSerial()方法时都会直接抛出java.lang.SecurityException异常
    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.O)
    public void getSerialByJavaApi(View view) {
        Log.d("Q_M", "----->" + Build.SERIAL);  //unknown
//        Log.d("Q_M", "----->" + "----" + Build.getSerial());   //崩溃
    }

    public void readMeme(View view) {
        parsePropInMemroy();
    }
}