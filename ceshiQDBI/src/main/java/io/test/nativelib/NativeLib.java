package io.test.nativelib;

public class NativeLib {

    // Used to load the 'nativelib' library on application startup.


    /**
     * A native method that is implemented by the 'nativelib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public static native String test_ceshi_qdbi();
}