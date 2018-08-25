package com.firstfloorsoftware.fluttersodium;

import android.os.AsyncTask;

import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.MethodCall;

import java.util.function.Function;

public class CryptoAsyncTask extends AsyncTask<MethodCall, Void, CryptoAsyncTaskResult> {
    private CryptoTask _task;
    private Result _result;

    public CryptoAsyncTask(CryptoTask task, Result result) {
        _task = task;
        _result = result;
    }

    protected CryptoAsyncTaskResult doInBackground(MethodCall... calls) {
        try {
            Object result = _task.execute(calls[0]);
            return new CryptoAsyncTaskResult(result);
        } catch (Exception e) {
            return new CryptoAsyncTaskResult(e);
        }
    }

    protected void onPostExecute(CryptoAsyncTaskResult result) {
        Exception e = result.getException();
        if (e != null) {
            FlutterSodiumPlugin.setError(_result, e);
        } else {
            _result.success(result.getResult());
        }
    }
}