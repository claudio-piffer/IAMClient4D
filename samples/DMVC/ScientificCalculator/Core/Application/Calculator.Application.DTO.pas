unit Calculator.Application.DTO;

{ Application layer: input and output of the use cases. Plain classes with
  properties: the presentation layer serializes them (JSON names in camelCase).
  The caller owns every object a use case returns. }

interface

uses
  System.Generics.Collections;

type
  TOperationResult = class
  private
    FOperation: string;
    FExpression: string;
    FValue: Double;
  public
    property Operation: string read FOperation write FOperation;
    property Expression: string read FExpression write FExpression;
    property Value: Double read FValue write FValue;
  end;

  TExpressionRequest = class
  private
    FExpression: string;
    FUnit: string;
  public
    /// <summary>e.g. 2 + 3 * sin(30); see Calculator.Domain.Expressions.</summary>
    property Expression: string read FExpression write FExpression;
    /// <summary>Angle unit of the trigonometric functions: deg (default) or rad.</summary>
    property &Unit: string read FUnit write FUnit;
  end;

  TPrimeAnalysis = class
  private
    FNumber: Int64;
    FIsPrime: Boolean;
    FFactors: TArray<Int64>;
  public
    property Number: Int64 read FNumber write FNumber;
    property IsPrime: Boolean read FIsPrime write FIsPrime;
    property Factors: TArray<Int64> read FFactors write FFactors;
  end;

  TCombinatorics = class
  private
    FN: Integer;
    FK: Integer;
    FCombinations: Double;
    FPermutations: Double;
  public
    property N: Integer read FN write FN;
    property K: Integer read FK write FK;
    property Combinations: Double read FCombinations write FCombinations;
    property Permutations: Double read FPermutations write FPermutations;
  end;

  TStatisticsRequest = class
  private
    FValues: TArray<Double>;
    FSample: Boolean;
  public
    property Values: TArray<Double> read FValues write FValues;
    /// <summary>True: sample statistics (n - 1); False: population.</summary>
    property Sample: Boolean read FSample write FSample;
  end;

  TStatisticsReport = class
  private
    FCount: Integer;
    FSum: Double;
    FMean: Double;
    FMedian: Double;
    FMinimum: Double;
    FMaximum: Double;
    FVariance: Double;
    FStandardDeviation: Double;
    FSample: Boolean;
  public
    property Count: Integer read FCount write FCount;
    property Sum: Double read FSum write FSum;
    property Mean: Double read FMean write FMean;
    property Median: Double read FMedian write FMedian;
    property Minimum: Double read FMinimum write FMinimum;
    property Maximum: Double read FMaximum write FMaximum;
    property Variance: Double read FVariance write FVariance;
    property StandardDeviation: Double read FStandardDeviation write FStandardDeviation;
    property Sample: Boolean read FSample write FSample;
  end;

  TQuadraticRequest = class
  private
    FA: Double;
    FB: Double;
    FC: Double;
  public
    property A: Double read FA write FA;
    property B: Double read FB write FB;
    property C: Double read FC write FC;
  end;

  TComplexValue = class
  private
    FRe: Double;
    FIm: Double;
  public
    constructor Create(const ARe, AIm: Double); reintroduce;
    property Re: Double read FRe write FRe;
    property Im: Double read FIm write FIm;
  end;

  TQuadraticReport = class
  private
    FEquation: string;
    FDiscriminant: Double;
    FKind: string;
    FRoots: TObjectList<TComplexValue>;
  public
    constructor Create;
    destructor Destroy; override;
    property Equation: string read FEquation write FEquation;
    property Discriminant: Double read FDiscriminant write FDiscriminant;
    /// <summary>two-real, one-real or complex.</summary>
    property Kind: string read FKind write FKind;
    property Roots: TObjectList<TComplexValue> read FRoots;
  end;

  TCalculationItem = class
  private
    FOperation: string;
    FExpression: string;
    FOutcome: string;
    FPerformedAt: string;
  public
    property Operation: string read FOperation write FOperation;
    property Expression: string read FExpression write FExpression;
    property Outcome: string read FOutcome write FOutcome;
    /// <summary>ISO 8601 in UTC, e.g. 2026-11-14T10:37:50.000Z.</summary>
    property PerformedAt: string read FPerformedAt write FPerformedAt;
  end;

  THistoryReport = class
  private
    FUserName: string;
    FItems: TObjectList<TCalculationItem>;
    function GetCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    property UserName: string read FUserName write FUserName;
    property Count: Integer read GetCount;
    property Items: TObjectList<TCalculationItem> read FItems;
  end;

  TClearHistoryReport = class
  private
    FRemoved: Integer;
  public
    property Removed: Integer read FRemoved write FRemoved;
  end;

  TConstantItem = class
  private
    FName: string;
    FSymbol: string;
    FValue: Double;
    FDescription: string;
  public
    property Name: string read FName write FName;
    property Symbol: string read FSymbol write FSymbol;
    property Value: Double read FValue write FValue;
    property Description: string read FDescription write FDescription;
  end;

  TConstantsReport = class
  private
    FItems: TObjectList<TConstantItem>;
  public
    constructor Create;
    destructor Destroy; override;
    property Items: TObjectList<TConstantItem> read FItems;
  end;

implementation

{ TComplexValue }

constructor TComplexValue.Create(const ARe, AIm: Double);
begin
  inherited Create;
  FRe := ARe;
  FIm := AIm;
end;

{ TQuadraticReport }

constructor TQuadraticReport.Create;
begin
  inherited Create;
  FRoots := TObjectList<TComplexValue>.Create(True);
end;

destructor TQuadraticReport.Destroy;
begin
  FRoots.Free;
  inherited;
end;

{ THistoryReport }

constructor THistoryReport.Create;
begin
  inherited Create;
  FItems := TObjectList<TCalculationItem>.Create(True);
end;

destructor THistoryReport.Destroy;
begin
  FItems.Free;
  inherited;
end;

function THistoryReport.GetCount: Integer;
begin
  Result := FItems.Count;
end;

{ TConstantsReport }

constructor TConstantsReport.Create;
begin
  inherited Create;
  FItems := TObjectList<TConstantItem>.Create(True);
end;

destructor TConstantsReport.Destroy;
begin
  FItems.Free;
  inherited;
end;

end.
