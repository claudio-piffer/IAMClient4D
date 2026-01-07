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
  Derived defines (DO NOT modify manually)

  These are automatically set based on IAM4D_TMS:
  - IAM4D_CRYPTO_LOCKBOX3: Active when using LockBox3 (default)
  - IAM4D_CRYPTO_TMS: Active when using TMS Cryptography Pack

  The crypto providers are MUTUALLY EXCLUSIVE - only one is compiled at a time.
------------------------------------------------------------------------------}
{$IFDEF IAM4D_TMS}
  {$DEFINE IAM4D_CRYPTO_TMS}
{$ELSE}
  {$DEFINE IAM4D_CRYPTO_LOCKBOX3}
{$ENDIF}
