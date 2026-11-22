(*------------------------------------------------------------------------------
  IAMClient4D Configuration

  This file contains conditional compilation symbols for optional features.
  Include this file at the beginning of units that need conditional features:

    {$I IAMClient4D.Config.inc}

  Alternatively, you can define these symbols in your project options:
    Project > Options > Delphi Compiler > Conditional defines
------------------------------------------------------------------------------}

{------------------------------------------------------------------------------
  TMS Cryptography Pack Support

  Enables TMS Cryptography Pack as an alternative crypto provider.
  This adds support for ECDSA algorithms (ES256, ES384, ES512) which are
  not available with the default LockBox3 provider.

  Requirements:
  - TMS Cryptography Pack installed (commercial license required)
  - TMS library path in project search path

  To enable: Uncomment the line below or add IAM4D_TMS to project defines
------------------------------------------------------------------------------*)
{.$DEFINE IAM4D_TMS}

{------------------------------------------------------------------------------
  TaurusTLS (OpenSSL) Support

  Uses OpenSSL 3.x/4.x libcrypto through the TaurusTLS headers.
  Supports RS*, PS*, ES* and AES-256-GCM token storage.

  Requirements:
  - TaurusTLS Source folder in project search path (Indy included with Delphi)
  - OpenSSL 3.x or 4.x libcrypto and libssl deployed with the application

  To enable: Uncomment the line below or add IAM4D_TAURUSTLS to project defines
------------------------------------------------------------------------------}
{.$DEFINE IAM4D_TAURUSTLS}

{------------------------------------------------------------------------------
  Derived defines (DO NOT modify manually)

  These are automatically set based on IAM4D_TMS / IAM4D_TAURUSTLS:
  - IAM4D_CRYPTO_LOCKBOX3: Active when using LockBox3 (default)
  - IAM4D_CRYPTO_TMS: Active when using TMS Cryptography Pack
  - IAM4D_CRYPTO_TAURUSTLS: Active when using TaurusTLS (OpenSSL)

  The crypto providers are MUTUALLY EXCLUSIVE - only one is compiled at a time.
------------------------------------------------------------------------------}
{$IF DEFINED(IAM4D_TMS) AND DEFINED(IAM4D_TAURUSTLS)}
  {$MESSAGE FATAL 'IAM4D_TMS and IAM4D_TAURUSTLS are mutually exclusive'}
{$ENDIF}

// Delphi 12 Athens (36.0): the version the library is built and tested with; older compilers fail
// with obscure errors (inline variables, managed record operators, RTL of Delphi 12)
{$IF CompilerVersion < 36.0}
  {$MESSAGE FATAL 'IAMClient4D requires Delphi 12 or later'}
{$ENDIF}

{$IF DEFINED(IAM4D_TMS)}
  {$DEFINE IAM4D_CRYPTO_TMS}
{$ELSEIF DEFINED(IAM4D_TAURUSTLS)}
  {$DEFINE IAM4D_CRYPTO_TAURUSTLS}
{$ELSE}
  {$DEFINE IAM4D_CRYPTO_LOCKBOX3}
{$ENDIF}
