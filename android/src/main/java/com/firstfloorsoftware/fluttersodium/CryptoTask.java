package com.firstfloorsoftware.fluttersodium;

import io.flutter.plugin.common.MethodCall;

public interface CryptoTask
{
  Object execute(MethodCall call) throws Exception;
}