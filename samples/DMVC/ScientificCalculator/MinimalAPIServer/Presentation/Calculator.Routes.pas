unit Calculator.Routes;

{ Presentation layer (Minimal API): the same API as the controller server,
  as route groups. Security is a stack of endpoint filters on each group:
  IAM4DJWTEndpointFilter validates the bearer token (401), RequireRoleEndpointFilter
  checks the role (403). The public group has no filter.
  RequireRoleEndpointFilter is the function of this unit, not the one of DMVC with the
  same name: it calls AContext.RequireAnyRole of IAMClient4D. Both compare roles
  case-sensitively; the 403 of IAMClient4D carries the Bearer challenge
  (insufficient_scope) and the message "Insufficient permissions". }

interface

uses
  MVCFramework,
  IAMClient4D.DMVC.Authenticator;

/// <summary>
/// AAuthenticator: one for every group, so that they share the JWKS cache.
/// </summary>
procedure ConfigureRoutes(const AEngine: TMVCEngine; const AAuthenticator: IIAM4DJWTAuthenticator);

implementation

uses
  System.SysUtils,
  MVCFramework.Commons,
  MVCFramework.MinimalAPI,
  IAMClient4D.DMVC.Filters,
  IAMClient4D.DMVC.Helpers,
  Calculator.Application.DTO,
  Calculator.Application.UseCases,
  Calculator.Presentation.Settings,
  Calculator.Presentation.Security,
  Calculator.Presentation.Requests,
  Calculator.Presentation.Composition;

type
  // Query strings, bound by name; a parameter without a default is required (400 if missing)
  TPowerQuery = record
    [MVCFromQueryString('base')]
    Base: Double;
    [MVCFromQueryString('exponent')]
    Exponent: Double;
  end;

  TRootQuery = record
    [MVCFromQueryString('value')]
    Value: Double;
    [MVCFromQueryString('degree', 2)]
    Degree: Integer;
  end;

  TLogQuery = record
    [MVCFromQueryString('value')]
    Value: Double;
    [MVCFromQueryString('base', 10)]
    Base: Double;
  end;

  // No string field: DMVC 3.5.0-rc10 leaks the managed fields of a bound
  // record, so "unit" is read from the context by the handler
  TTrigQuery = record
    [MVCFromQueryString('value')]
    Value: Double;
  end;

  TCombinatoricsQuery = record
    [MVCFromQueryString('n')]
    N: Integer;
    [MVCFromQueryString('k')]
    K: Integer;
  end;

/// <summary>403 + WWW-Authenticate insufficient_scope without ARole.</summary>
function RequireRoleEndpointFilter(const ARole: string): TMVCEndpointFilter;
begin
  Result :=
    function(const AContext: TWebContext; const ANext: TMVCEndpointFilterNext): IMVCResponse
    begin
      AContext.RequireAnyRole([ARole]);
      Result := ANext();
    end;
end;

procedure MapPublic(const AEngine: TMVCEngine);
var
  LGroup: TMVCRouteGroup<TObject>;
begin
  LGroup := AEngine.Prefix('/api');

  LGroup.MapGet('/info',
    function: IMVCResponse
    begin
      Result := Ok(TServiceInfo.Create(Settings, 'minimal-api'));
    end)
    .WithSummary('Service description')
    .WithDescription('Where to get a token and which roles the API checks. No token needed.')
    .WithTags('Public')
    .Produces<TServiceInfo>;

  LGroup.MapGet<ICalculatorService>('/constants',
    function(ACalculator: ICalculatorService): IMVCResponse
    begin
      Result := Ok(ACalculator.Constants);
    end)
    .WithSummary('Mathematical constants')
    .WithDescription('No token needed.')
    .WithTags('Public')
    .Produces<TConstantsReport>;
end;

procedure MapMath(const AEngine: TMVCEngine; const AAuthenticator: IIAM4DJWTAuthenticator);
var
  LElementary, LTrigonometry, LExpressions, LNumberTheory: TMVCRouteGroup<TObject>;
begin
  LElementary := AEngine.Prefix('/api/elementary')
    .Use(IAM4DJWTEndpointFilter(AAuthenticator))
    .Use(RequireRoleEndpointFilter(ROLE_CALCULATOR_USER));

  LElementary.MapGet<TPowerQuery, ICalculatorService, TWebContext>('/power',
    function(AQuery: TPowerQuery; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.Power(CallerOf(AContext), AQuery.Base, AQuery.Exponent));
    end)
    .WithSummary('base ^ exponent')
    .WithDescription('Role: calculator-user.')
    .WithTags('Elementary')
    .Produces<TOperationResult>;

  LElementary.MapGet<TRootQuery, ICalculatorService, TWebContext>('/root',
    function(AQuery: TRootQuery; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.Root(CallerOf(AContext), AQuery.Value, AQuery.Degree));
    end)
    .WithSummary('Real root of the given degree')
    .WithDescription('Odd roots of negative numbers too. Role: calculator-user.')
    .WithTags('Elementary')
    .Produces<TOperationResult>;

  LElementary.MapGet<TLogQuery, ICalculatorService, TWebContext>('/log',
    function(AQuery: TLogQuery; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.Logarithm(CallerOf(AContext), AQuery.Value, AQuery.Base));
    end)
    .WithSummary('Logarithm in the given base (default 10)')
    .WithDescription('Role: calculator-user.')
    .WithTags('Elementary')
    .Produces<TOperationResult>;

  LElementary.MapGet<Integer, ICalculatorService, TWebContext>('/factorial/($n)',
    function(AN: Integer; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.Factorial(CallerOf(AContext), AN));
    end)
    .WithSummary('n! for n between 0 and 170')
    .WithDescription('Role: calculator-user.')
    .WithTags('Elementary')
    .Produces<TOperationResult>;

  LTrigonometry := AEngine.Prefix('/api/trigonometry')
    .Use(IAM4DJWTEndpointFilter(AAuthenticator))
    .Use(RequireRoleEndpointFilter(ROLE_CALCULATOR_USER));

  LTrigonometry.MapGet<string, TTrigQuery, ICalculatorService, TWebContext>('/($fn)',
    function(AFunction: string; AQuery: TTrigQuery; ACalculator: ICalculatorService;
      AContext: TWebContext): IMVCResponse
    var
      LUnit: string;
    begin
      LUnit := AContext.Request.QueryStringParam('unit');
      if LUnit.IsEmpty then
        LUnit := 'deg';
      Result := Ok(ACalculator.Trigonometric(CallerOf(AContext), AFunction, AQuery.Value, LUnit));
    end)
    .WithSummary('sin, cos, tan, asin, acos, atan')
    .WithDescription('Direct functions take an angle, inverse ones return an angle. ' +
      'unit: deg (default) or rad. Role: calculator-user.')
    .WithTags('Trigonometry')
    .Produces<TOperationResult>;

  LExpressions := AEngine.Prefix('/api/expressions')
    .Use(IAM4DJWTEndpointFilter(AAuthenticator))
    .Use(RequireRoleEndpointFilter(ROLE_CALCULATOR_USER));

  LExpressions.MapPost<TExpressionRequest, ICalculatorService, TWebContext>('/evaluate',
    function(ARequest: TExpressionRequest; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.Evaluate(CallerOf(AContext), ARequest));
    end)
    .WithSummary('Value of an arithmetic expression')
    .WithDescription('Body {"expression": "2 + 3 * sin(30)", "unit": "deg"}. Numbers (decimal point, 1.5E3), ' +
      '+ - * / ^, unary minus, parentheses, postfix !, implicit multiplication (2pi), constants pi e tau phi, ' +
      'functions sin cos tan asin acos atan sqrt cbrt ln log abs exp; unit deg (default) or rad. Role: calculator-user.')
    .WithTags('Expressions')
    .Produces<TOperationResult>;

  LNumberTheory := AEngine.Prefix('/api/number-theory')
    .Use(IAM4DJWTEndpointFilter(AAuthenticator))
    .Use(RequireRoleEndpointFilter(ROLE_CALCULATOR_USER));

  LNumberTheory.MapGet<Int64, ICalculatorService, TWebContext>('/prime/($n)',
    function(AN: Int64; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.AnalyzeNumber(CallerOf(AContext), AN));
    end)
    .WithSummary('Primality and prime factors of n (2 to 10^12)')
    .WithDescription('Role: calculator-user.')
    .WithTags('Number theory')
    .Produces<TPrimeAnalysis>;

  LNumberTheory.MapGet<TCombinatoricsQuery, ICalculatorService, TWebContext>('/combinatorics',
    function(AQuery: TCombinatoricsQuery; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.Combinatorics(CallerOf(AContext), AQuery.N, AQuery.K));
    end)
    .WithSummary('Combinations and permutations of k out of n (n up to 1000)')
    .WithDescription('Role: calculator-user.')
    .WithTags('Number theory')
    .Produces<TCombinatorics>;
end;

procedure MapAdvanced(const AEngine: TMVCEngine; const AAuthenticator: IIAM4DJWTAuthenticator);
begin
  AEngine.Prefix('/api/statistics')
    .Use(IAM4DJWTEndpointFilter(AAuthenticator))
    .Use(RequireRoleEndpointFilter(ROLE_CALCULATOR_ADVANCED))
    .MapPost<ICalculatorService, TWebContext>('/describe',
      function(ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
      var
        LRequest: TStatisticsRequest;
      begin
        // Body read by hand: see Calculator.Presentation.Requests
        LRequest := StatisticsRequestFromBody(AContext);
        try
          Result := Ok(ACalculator.DescribeStatistics(CallerOf(AContext), LRequest));
        finally
          LRequest.Free;
        end;
      end)
    .WithSummary('Descriptive statistics')
    .WithDescription('Body: {"values": [numbers], "sample": boolean}. ' +
      'Count, sum, mean, median, min, max, variance and standard deviation. ' +
      'sample = true: sample statistics (n - 1). Role: calculator-advanced.')
    .WithTags('Statistics')
    .Produces<TStatisticsReport>;

  AEngine.Prefix('/api/equations')
    .Use(IAM4DJWTEndpointFilter(AAuthenticator))
    .Use(RequireRoleEndpointFilter(ROLE_CALCULATOR_ADVANCED))
    .MapPost<TQuadraticRequest, ICalculatorService, TWebContext>('/quadratic',
      function(ARequest: TQuadraticRequest; ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
      begin
        Result := Ok(ACalculator.SolveQuadratic(CallerOf(AContext), ARequest));
      end)
    .WithSummary('Roots of a x^2 + b x + c = 0')
    .WithDescription('Real or complex roots. Role: calculator-advanced.')
    .WithTags('Equations')
    .Produces<TQuadraticReport>;
end;

procedure MapAccount(const AEngine: TMVCEngine; const AAuthenticator: IIAM4DJWTAuthenticator);
var
  LGroup: TMVCRouteGroup<TObject>;
begin
  // Any valid token: no role filter
  LGroup := AEngine.Prefix('/api').Use(IAM4DJWTEndpointFilter(AAuthenticator));

  LGroup.MapGet<TWebContext>('/me',
    function(AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(UserProfileOf(AContext));
    end)
    .WithSummary('Who the token says you are')
    .WithDescription('And the roles the API sees.')
    .WithTags('Account')
    .Produces<TUserProfile>;

  LGroup.MapGet<ICalculatorService, TWebContext>('/history',
    function(ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.History(CallerOf(AContext)));
    end)
    .WithSummary('Your last calculations')
    .WithDescription('Most recent first, kept in memory.')
    .WithTags('Account')
    .Produces<THistoryReport>;

  LGroup.MapDelete<ICalculatorService, TWebContext>('/history',
    function(ACalculator: ICalculatorService; AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(ACalculator.ClearHistory(CallerOf(AContext)));
    end)
    .WithSummary('Deletes your history')
    .WithTags('Account')
    .Produces<TClearHistoryReport>;
end;

procedure ConfigureRoutes(const AEngine: TMVCEngine; const AAuthenticator: IIAM4DJWTAuthenticator);
begin
  MapPublic(AEngine);
  MapMath(AEngine, AAuthenticator);
  MapAdvanced(AEngine, AAuthenticator);
  MapAccount(AEngine, AAuthenticator);
end;

end.
