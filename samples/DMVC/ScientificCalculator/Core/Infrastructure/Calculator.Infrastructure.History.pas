unit Calculator.Infrastructure.History;

{ Infrastructure layer: in-memory history (lost on restart). A database
  implementation of ICalculationHistory would replace it without touching
  the use cases. }

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Calculator.Domain.Calculation,
  Calculator.Application.Ports;

type
  TInMemoryCalculationHistory = class(TInterfacedObject, ICalculationHistory)
  public const
    DEFAULT_CAPACITY = 50;
  private
    FLock: TObject;
    FCapacity: Integer;
    FItems: TObjectDictionary<string, TList<TCalculation>>;
  public
    /// <summary>ACapacity: calculations kept per user (oldest dropped).</summary>
    constructor Create(const ACapacity: Integer = DEFAULT_CAPACITY);
    destructor Destroy; override;
    procedure Add(const ASubject: string; const ACalculation: TCalculation);
    function List(const ASubject: string): TArray<TCalculation>;
    function Clear(const ASubject: string): Integer;
  end;

  TSystemClock = class(TInterfacedObject, IClock)
  public
    function NowUTC: TDateTime;
  end;

implementation

uses
  System.DateUtils;

{ TInMemoryCalculationHistory }

constructor TInMemoryCalculationHistory.Create(const ACapacity: Integer);
begin
  inherited Create;
  if ACapacity < 1 then
    raise EArgumentOutOfRangeException.Create('TInMemoryCalculationHistory: capacity must be at least 1');
  FCapacity := ACapacity;
  FLock := TObject.Create;
  FItems := TObjectDictionary<string, TList<TCalculation>>.Create([doOwnsValues]);
end;

destructor TInMemoryCalculationHistory.Destroy;
begin
  FItems.Free;
  FLock.Free;
  inherited;
end;

procedure TInMemoryCalculationHistory.Add(const ASubject: string; const ACalculation: TCalculation);
var
  LList: TList<TCalculation>;
begin
  TMonitor.Enter(FLock);
  try
    if not FItems.TryGetValue(ASubject, LList) then
    begin
      LList := TList<TCalculation>.Create;
      FItems.Add(ASubject, LList);
    end;
    LList.Insert(0, ACalculation); // most recent first
    if LList.Count > FCapacity then
      LList.Count := FCapacity;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TInMemoryCalculationHistory.List(const ASubject: string): TArray<TCalculation>;
var
  LList: TList<TCalculation>;
begin
  TMonitor.Enter(FLock);
  try
    if FItems.TryGetValue(ASubject, LList) then
      Result := LList.ToArray
    else
      Result := nil;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TInMemoryCalculationHistory.Clear(const ASubject: string): Integer;
var
  LList: TList<TCalculation>;
begin
  TMonitor.Enter(FLock);
  try
    if FItems.TryGetValue(ASubject, LList) then
    begin
      Result := LList.Count;
      FItems.Remove(ASubject);
    end
    else
      Result := 0;
  finally
    TMonitor.Exit(FLock);
  end;
end;

{ TSystemClock }

function TSystemClock.NowUTC: TDateTime;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now);
end;

end.
