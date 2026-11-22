{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.IdentityProvider.Keycloak.Async.pas
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

  Async wrapper of the Keycloak identity provider manager: each call runs the
  synchronous operation on a worker thread (TAsyncCore.New).

  ---------------------------------------------------------------------------
}

unit IAMClient4D.IdentityProvider.Keycloak.Async;

interface

uses
  System.SysUtils,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.IdentityProvider.Core,
  IAMClient4D.IdentityProvider.Keycloak;

type
  /// <summary>
  /// Async wrapper for TIAM4DKeycloakIdentityProviderManager (VCL/FMX).
  /// </summary>
  /// <remarks>
  /// Callbacks run on the main thread by default. Server code should use
  /// IIAM4DIdentityProviderManager directly.
  /// Each operation holds its own reference to the sync manager: the wrapper can be released
  /// (e.g. form closed) while operations run.
  /// </remarks>
  TIAM4DKeycloakIdentityProviderManagerAsync = class(TInterfacedObject, IIAM4DIdentityProviderManagerAsync)
  private
    FSyncManager: IIAM4DIdentityProviderManager;
  public
    constructor Create(const ASyncManager: IIAM4DIdentityProviderManager); overload;
    constructor Create(const AClient: IIAM4DClient; const ABaseURL: string = ''; const ARealm: string = ''); overload;
    constructor Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string); overload;

    function GetIdentityProvidersAsync: IAsyncPromise<TArray<TIAM4DIdentityProvider>>; overload;
    function GetIdentityProvidersAsync(const ASearch: string; const AFirst, AMax: Integer): IAsyncPromise<TArray<TIAM4DIdentityProvider>>; overload;
    function GetIdentityProviderAsync(const AAlias: string): IAsyncPromise<TIAM4DIdentityProvider>;
    function TryGetIdentityProviderAsync(const AAlias: string): IAsyncPromise<TIAM4DIdentityProviderTryResult>;
    function CreateIdentityProviderAsync(const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
    function UpdateIdentityProviderAsync(const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
    function SaveIdentityProviderAsync(const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
    function DeleteIdentityProviderAsync(const AAlias: string): IAsyncVoidPromise;
    function IsProviderInstalledAsync(const AProviderID: string): IAsyncPromise<Boolean>;
    function ImportConfigAsync(const AProviderID: string; const AFromURL: string): IAsyncPromise<TIAM4DConfigMap>;
    function ExportServiceProviderMetadataAsync(const AAlias: string): IAsyncPromise<string>;
    function GetMappersAsync(const AIdentityProviderAlias: string): IAsyncPromise<TArray<TIAM4DIdentityProviderMapper>>;
    function GetMapperAsync(const AIdentityProviderAlias: string; const AMapperID: string): IAsyncPromise<TIAM4DIdentityProviderMapper>;
    function GetMapperTypesAsync(const AIdentityProviderAlias: string): IAsyncPromise<TArray<TIAM4DIdentityProviderMapperType>>;
    function CreateMapperAsync(const AMapper: TIAM4DIdentityProviderMapper): IAsyncPromise<string>;
    function UpdateMapperAsync(const AMapper: TIAM4DIdentityProviderMapper): IAsyncVoidPromise;
    function DeleteMapperAsync(const AIdentityProviderAlias: string; const AMapperID: string): IAsyncVoidPromise;
  end;

implementation

{ TIAM4DKeycloakIdentityProviderManagerAsync }

constructor TIAM4DKeycloakIdentityProviderManagerAsync.Create(const ASyncManager: IIAM4DIdentityProviderManager);
begin
  inherited Create;
  FSyncManager := ASyncManager;
end;

constructor TIAM4DKeycloakIdentityProviderManagerAsync.Create(const AClient: IIAM4DClient; const ABaseURL: string;
  const ARealm: string);
begin
  Create(TIAM4DKeycloakIdentityProviderManager.Create(AClient, ABaseURL, ARealm) as IIAM4DIdentityProviderManager);
end;

constructor TIAM4DKeycloakIdentityProviderManagerAsync.Create(const AAccessToken: string; const ABaseURL: string;
  const ARealm: string);
begin
  Create(TIAM4DKeycloakIdentityProviderManager.Create(AAccessToken, ABaseURL, ARealm) as IIAM4DIdentityProviderManager);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.GetIdentityProvidersAsync: IAsyncPromise<TArray<TIAM4DIdentityProvider>>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TArray<TIAM4DIdentityProvider>>(
    function(const AOperation: IAsyncOperation): TArray<TIAM4DIdentityProvider>
    begin
      Result := LSyncManager.GetIdentityProviders;
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.GetIdentityProvidersAsync(const ASearch: string;
  const AFirst, AMax: Integer): IAsyncPromise<TArray<TIAM4DIdentityProvider>>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TArray<TIAM4DIdentityProvider>>(
    function(const AOperation: IAsyncOperation): TArray<TIAM4DIdentityProvider>
    begin
      Result := LSyncManager.GetIdentityProviders(ASearch, AFirst, AMax);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.GetIdentityProviderAsync(
  const AAlias: string): IAsyncPromise<TIAM4DIdentityProvider>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TIAM4DIdentityProvider>(
    function(const AOperation: IAsyncOperation): TIAM4DIdentityProvider
    begin
      Result := LSyncManager.GetIdentityProvider(AAlias);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.TryGetIdentityProviderAsync(
  const AAlias: string): IAsyncPromise<TIAM4DIdentityProviderTryResult>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TIAM4DIdentityProviderTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DIdentityProviderTryResult
    begin
      Result := LSyncManager.TryGetIdentityProvider(AAlias);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.CreateIdentityProviderAsync(
  const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSyncManager.CreateIdentityProvider(AIdentityProvider);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.UpdateIdentityProviderAsync(
  const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSyncManager.UpdateIdentityProvider(AIdentityProvider);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.SaveIdentityProviderAsync(
  const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSyncManager.SaveIdentityProvider(AIdentityProvider);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.DeleteIdentityProviderAsync(const AAlias: string): IAsyncVoidPromise;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSyncManager.DeleteIdentityProvider(AAlias);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.IsProviderInstalledAsync(
  const AProviderID: string): IAsyncPromise<Boolean>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    begin
      Result := LSyncManager.IsProviderInstalled(AProviderID);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.ImportConfigAsync(const AProviderID: string;
  const AFromURL: string): IAsyncPromise<TIAM4DConfigMap>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TIAM4DConfigMap>(
    function(const AOperation: IAsyncOperation): TIAM4DConfigMap
    begin
      Result := LSyncManager.ImportConfig(AProviderID, AFromURL);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.ExportServiceProviderMetadataAsync(
  const AAlias: string): IAsyncPromise<string>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LSyncManager.ExportServiceProviderMetadata(AAlias);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.GetMappersAsync(
  const AIdentityProviderAlias: string): IAsyncPromise<TArray<TIAM4DIdentityProviderMapper>>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TArray<TIAM4DIdentityProviderMapper>>(
    function(const AOperation: IAsyncOperation): TArray<TIAM4DIdentityProviderMapper>
    begin
      Result := LSyncManager.GetMappers(AIdentityProviderAlias);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.GetMapperAsync(const AIdentityProviderAlias: string;
  const AMapperID: string): IAsyncPromise<TIAM4DIdentityProviderMapper>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TIAM4DIdentityProviderMapper>(
    function(const AOperation: IAsyncOperation): TIAM4DIdentityProviderMapper
    begin
      Result := LSyncManager.GetMapper(AIdentityProviderAlias, AMapperID);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.GetMapperTypesAsync(
  const AIdentityProviderAlias: string): IAsyncPromise<TArray<TIAM4DIdentityProviderMapperType>>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<TArray<TIAM4DIdentityProviderMapperType>>(
    function(const AOperation: IAsyncOperation): TArray<TIAM4DIdentityProviderMapperType>
    begin
      Result := LSyncManager.GetMapperTypes(AIdentityProviderAlias);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.CreateMapperAsync(
  const AMapper: TIAM4DIdentityProviderMapper): IAsyncPromise<string>;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LSyncManager.CreateMapper(AMapper);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.UpdateMapperAsync(
  const AMapper: TIAM4DIdentityProviderMapper): IAsyncVoidPromise;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSyncManager.UpdateMapper(AMapper);
    end);
end;

function TIAM4DKeycloakIdentityProviderManagerAsync.DeleteMapperAsync(const AIdentityProviderAlias: string;
  const AMapperID: string): IAsyncVoidPromise;
begin
  var LSyncManager := FSyncManager;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSyncManager.DeleteMapper(AIdentityProviderAlias, AMapperID);
    end);
end;

end.
