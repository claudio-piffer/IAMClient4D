{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.JSONUtils.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2025 Claudio Piffer
  License    : Apache License, Version 2.0, January 2004
  Source URL : https://github.com/claudio-piffer/IAMClient4D

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ---------------------------------------------------------------------------
}

unit IAMClient4D.Common.JSONUtils;

interface

uses
  System.SysUtils,
  System.JSON,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Utility class for safe JSON parsing operations.
  /// </summary>
  /// <remarks>
  /// Provides safe parsing methods with proper error handling and memory management.
  /// Safe* methods raise exceptions on parsing failures.
  /// Try* methods return boolean success status without raising exceptions.
  /// All methods are static and thread-safe.
  /// Memory: Caller is responsible for freeing returned JSON objects.
  /// </remarks>
  TIAM4DJSONUtils = class
  public
    /// <summary>
    /// Parses JSON string to TJSONObject, raises exception on failure
    /// </summary>
    class function SafeParseJSONObject(const AJSONString: string; const AErrorContext: string = ''): TJSONObject;

    /// <summary>
    /// Parses JSON string to TJSONArray, raises exception on failure
    /// </summary>
    class function SafeParseJSONArray(const AJSONString: string; const AErrorContext: string = ''): TJSONArray;

    /// <summary>
    /// Tries to parse JSON string to TJSONObject, returns success status
    /// </summary>
    class function TryParseJSONObject(const AJSONString: string; out AJSONObject: TJSONObject): Boolean;

    /// <summary>
    /// Tries to parse JSON string to TJSONArray, returns success status
    /// </summary>
    class function TryParseJSONArray(const AJSONString: string; out AJSONArray: TJSONArray): Boolean;

    /// <summary>
    /// Parses JSON string to TJSONValue, raises exception on failure
    /// </summary>
    class function SafeParseJSONValue(const AJSONString: string; const AErrorContext: string = ''): TJSONValue;
  end;

implementation

{ TIAM4DJSONUtils }

class function TIAM4DJSONUtils.SafeParseJSONObject(const AJSONString: string; const AErrorContext: string): TJSONObject;
var
  LJSONValue: TJSONValue;
  LErrorMsg: string;
begin
  LJSONValue := nil;

  try
    LJSONValue := TJSONObject.ParseJSONValue(AJSONString);
    if LJSONValue = nil then
    begin
      if AErrorContext <> '' then
        LErrorMsg := Format('Failed to parse JSON for %s: invalid JSON syntax', [AErrorContext])
      else
        LErrorMsg := 'Failed to parse JSON: invalid JSON syntax';
      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;

    if not (LJSONValue is TJSONObject) then
    begin
      if AErrorContext <> '' then
        LErrorMsg := Format('Expected JSON object for %s, but got %s', [AErrorContext, LJSONValue.ClassName])
      else
        LErrorMsg := Format('Expected JSON object, but got %s', [LJSONValue.ClassName]);

      LJSONValue.Free;
      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;

    Result := LJSONValue as TJSONObject;
  except
    on E: EIAM4DJSONParseException do
      raise;
    on E: Exception do
    begin
      if Assigned(LJSONValue) then
        LJSONValue.Free;

      if AErrorContext <> '' then
        LErrorMsg := Format('JSON parsing error for %s: %s', [AErrorContext, E.Message])
      else
        LErrorMsg := Format('JSON parsing error: %s', [E.Message]);

      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;
  end;
end;

class function TIAM4DJSONUtils.SafeParseJSONArray(const AJSONString: string; const AErrorContext: string): TJSONArray;
var
  LJSONValue: TJSONValue;
  LErrorMsg: string;
begin
  LJSONValue := nil;

  try
    LJSONValue := TJSONObject.ParseJSONValue(AJSONString);
    if LJSONValue = nil then
    begin
      if AErrorContext <> '' then
        LErrorMsg := Format('Failed to parse JSON for %s: invalid JSON syntax', [AErrorContext])
      else
        LErrorMsg := 'Failed to parse JSON: invalid JSON syntax';
      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;

    if not (LJSONValue is TJSONArray) then
    begin
      if AErrorContext <> '' then
        LErrorMsg := Format('Expected JSON array for %s, but got %s', [AErrorContext, LJSONValue.ClassName])
      else
        LErrorMsg := Format('Expected JSON array, but got %s', [LJSONValue.ClassName]);

      LJSONValue.Free;
      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;

    Result := LJSONValue as TJSONArray;
  except
    on E: EIAM4DJSONParseException do
      raise;
    on E: Exception do
    begin
      if Assigned(LJSONValue) then
        LJSONValue.Free;

      if AErrorContext <> '' then
        LErrorMsg := Format('JSON parsing error for %s: %s', [AErrorContext, E.Message])
      else
        LErrorMsg := Format('JSON parsing error: %s', [E.Message]);

      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;
  end;
end;

class function TIAM4DJSONUtils.TryParseJSONObject(const AJSONString: string; out AJSONObject: TJSONObject): Boolean;
var
  LJSONValue: TJSONValue;
begin
  AJSONObject := nil;
  LJSONValue := nil;

  try
    LJSONValue := TJSONObject.ParseJSONValue(AJSONString);
    if LJSONValue = nil then
      Exit(False);

    if not (LJSONValue is TJSONObject) then
    begin
      LJSONValue.Free;
      Exit(False);
    end;

    AJSONObject := LJSONValue as TJSONObject;
    Result := True;
  except
    if Assigned(LJSONValue) then
      LJSONValue.Free;
    AJSONObject := nil;
    Result := False;
  end;
end;

class function TIAM4DJSONUtils.TryParseJSONArray(const AJSONString: string; out AJSONArray: TJSONArray): Boolean;
var
  LJSONValue: TJSONValue;
begin
  AJSONArray := nil;
  LJSONValue := nil;

  try
    LJSONValue := TJSONObject.ParseJSONValue(AJSONString);
    if LJSONValue = nil then
      Exit(False);

    if not (LJSONValue is TJSONArray) then
    begin
      LJSONValue.Free;
      Exit(False);
    end;

    AJSONArray := LJSONValue as TJSONArray;
    Result := True;
  except
    if Assigned(LJSONValue) then
      LJSONValue.Free;
    AJSONArray := nil;
    Result := False;
  end;
end;

class function TIAM4DJSONUtils.SafeParseJSONValue(const AJSONString: string; const AErrorContext: string): TJSONValue;
var
  LErrorMsg: string;
begin
  Result := nil;

  try
    Result := TJSONObject.ParseJSONValue(AJSONString);
    if Result = nil then
    begin
      if AErrorContext <> '' then
        LErrorMsg := Format('Failed to parse JSON for %s: invalid JSON syntax', [AErrorContext])
      else
        LErrorMsg := 'Failed to parse JSON: invalid JSON syntax';
      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;
  except
    on E: EIAM4DJSONParseException do
      raise;
    on E: Exception do
    begin
      if Assigned(Result) then
        FreeAndNil(Result);

      if AErrorContext <> '' then
        LErrorMsg := Format('JSON parsing error for %s: %s', [AErrorContext, E.Message])
      else
        LErrorMsg := Format('JSON parsing error: %s', [E.Message]);

      raise EIAM4DJSONParseException.Create(LErrorMsg);
    end;
  end;
end;

end.