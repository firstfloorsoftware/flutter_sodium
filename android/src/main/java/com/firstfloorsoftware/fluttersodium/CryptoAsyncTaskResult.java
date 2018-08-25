package com.firstfloorsoftware.fluttersodium;

public class CryptoAsyncTaskResult {
    private Object _result;
    private Exception _exception;

    public CryptoAsyncTaskResult(Object result) {
        _result = result;
    }

    public CryptoAsyncTaskResult(Exception exception) {
        _exception = exception;
    }

    public Object getResult() {
        return _result;
    }

    public Exception getException() {
        return _exception;
    }
}