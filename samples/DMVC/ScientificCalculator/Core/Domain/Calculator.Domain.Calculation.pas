unit Calculator.Domain.Calculation;

{ Domain layer: a calculation done by a user, kept in the history. }

interface

type
  TCalculation = record
    Operation: string;
    Expression: string;
    Outcome: string;
    PerformedAt: TDateTime; // UTC
    class function Create(const AOperation, AExpression, AOutcome: string;
      const APerformedAt: TDateTime): TCalculation; static;
  end;

implementation

class function TCalculation.Create(const AOperation, AExpression, AOutcome: string;
  const APerformedAt: TDateTime): TCalculation;
begin
  Result.Operation := AOperation;
  Result.Expression := AExpression;
  Result.Outcome := AOutcome;
  Result.PerformedAt := APerformedAt;
end;

end.
