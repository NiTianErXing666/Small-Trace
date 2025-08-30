package io.calvin.qdbi;

import static io.test.nativelib.NativeLib.test_ceshi_qdbi;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

import io.calvin.qdbi.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'qdbi' library on application startup.
    static {
        System.loadLibrary("qdbi");
    }
    static {
        System.loadLibrary("nativelib");
    }
    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());

        Button button = findViewById(R.id.button);
        button.setOnClickListener(v -> {
            test_qdbi();
        });

        Button button2 = findViewById(R.id.button2);
        button2.setOnClickListener(v -> {
            test_gum();
        });

        Button button3 = findViewById(R.id.button3);
        button3.setOnClickListener(v -> {
            test_open();
        });
        Button button4 = findViewById(R.id.button4);
        button4.setOnClickListener(v -> {
            test_svc();
        });

        Button button5 = findViewById(R.id.button5);
        button5.setOnClickListener(v -> {
            test_soinfo();
        });

        Button button6 = findViewById(R.id.button6);
        button6.setOnClickListener(v -> {
            test_hook_trace();
        });

        Button button7 = findViewById(R.id.button7);
        button7.setOnClickListener(v -> {
            test_hook_trace_test();
        });

        Button button8 = findViewById(R.id.button8);
        button8.setOnClickListener(v -> {
            test_ceshi_qdbi_hook();
        });

        Button button9 = findViewById(R.id.button9);
        button9.setOnClickListener(v -> {
            Log.d("TAG", "onCreate: "+test_ceshi_qdbi());
        });

    }

    private native void test_ceshi_qdbi_hook();

    private native void test_hook_trace();

    private native void test_hook_trace_test();

    private native void test_qdbi();


    private native void test_gum();

    private native void test_open();

    private native void test_soinfo();


    private native void test_svc();
    /**
     * A native method that is implemented by the 'qdbi' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}