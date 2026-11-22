{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Androidapi.CustomTabs.pas
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

unit IAMClient4D.Androidapi.CustomTabs;

{ JNI import of the part of androidx.browser.customtabs used to open the login in a Custom Tab.
  Needs browser-1.8.0.dex.jar in the Java libraries of the project (enabled by default in Delphi 13). }

interface

{$IFDEF ANDROID}
uses
  Androidapi.JNIBridge,
  Androidapi.JNI.JavaTypes,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.JNI.Net;

type
  JCustomTabsIntent = interface;
  JCustomTabsIntent_Builder = interface;

  JCustomTabsIntentClass = interface(JObjectClass)
    ['{7B1C4E52-3A0D-4F6B-9E21-5D8A0C3F6A11}']
  end;

  [JavaSignature('androidx/browser/customtabs/CustomTabsIntent')]
  JCustomTabsIntent = interface(JObject)
    ['{2E9D6A30-84C1-4B7F-A5D3-1F0B7C92E4A8}']
    procedure launchUrl(context: JContext; url: Jnet_Uri); cdecl;
  end;
  TJCustomTabsIntent = class(TJavaGenericImport<JCustomTabsIntentClass, JCustomTabsIntent>)
  end;

  JCustomTabsIntent_BuilderClass = interface(JObjectClass)
    ['{C4F08B17-6E35-49A2-8D70-A3B1E5D92F06}']
    function init: JCustomTabsIntent_Builder; cdecl;
  end;

  [JavaSignature('androidx/browser/customtabs/CustomTabsIntent$Builder')]
  JCustomTabsIntent_Builder = interface(JObject)
    ['{91A5D2E8-0B74-4C3F-B6E9-48D7F1C03A5B}']
    function setShowTitle(showTitle: Boolean): JCustomTabsIntent_Builder; cdecl;
    function build: JCustomTabsIntent; cdecl;
  end;
  TJCustomTabsIntent_Builder = class(TJavaGenericImport<JCustomTabsIntent_BuilderClass, JCustomTabsIntent_Builder>)
  end;
{$ENDIF}

implementation

end.
