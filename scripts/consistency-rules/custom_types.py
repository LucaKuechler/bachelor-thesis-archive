import yaml
from pydantic import BaseModel, field_validator


class SIGMARuleConvertionRequest(BaseModel):
    rule: str
    format: str
    custom_pipeline: str

    @field_validator("rule")
    def rule_valid(cls, value) -> str:
        try:
            _ = yaml.safe_load(value)

        except yaml.YAMLError as e:
            raise ValueError(f"SIGMA Rule input should be valid YAML: {e}")

        return value

    @field_validator("custom_pipeline")
    def custom_pipeline_valid(cls, value) -> str:
        if value == "":
            return value

        try:
            # custom pipeline is an optional parameter
            _ = yaml.safe_load(value)

        except yaml.YAMLError as e:
            raise ValueError(f"Pipeline input should be valid YAML: {e}")

        return value

    def has_pipeline(self) -> bool:
        return self.custom_pipeline != ""
