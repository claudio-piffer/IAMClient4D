unit Calculator.Application.Ports;

{ Application layer: what the use cases need from the outside world.
  Implemented by the infrastructure layer, wired by the composition root. }

interface

uses
  Calculator.Domain.Calculation;

type
  /// <summary>History of the calculations, one list per user. Thread-safe.</summary>
  ICalculationHistory = interface
    ['{3E8B6F21-7C4D-4A95-B1E0-2F6D9C8A7B13}']
    procedure Add(const ASubject: string; const ACalculation: TCalculation);
    /// <summary>Most recent first.</summary>
    function List(const ASubject: string): TArray<TCalculation>;
    /// <summary>Returns the number of removed calculations.</summary>
    function Clear(const ASubject: string): Integer;
  end;

  /// <summary>Current time in UTC: replaceable in tests.</summary>
  IClock = interface
    ['{9A4C2E7B-1F3D-4B86-A5E9-0C7D8B6F2A41}']
    function NowUTC: TDateTime;
  end;

implementation

end.
