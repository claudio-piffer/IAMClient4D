{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Attributes.pas
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

unit IAMClient4D.DMVC.Attributes;

interface

type
  /// <summary>
  /// Marks a controller class or action method as publicly accessible,
  /// bypassing JWT authentication in the IAM4D middleware.
  /// When applied to a class, all actions in that controller are public.
  /// When applied to a method, only that specific action is public.
  /// Public endpoints can still access JWT claims if a valid token is provided.
  /// </summary>
  IAM4DPublicAttribute = class(TCustomAttribute);

implementation

end.
