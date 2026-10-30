"""Executable matching protocol; case labels remain on the evaluator host."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    target: str
    check_id: str
    family: str
    route: str = Field(pattern=r"^/")
    label: Literal["vulnerable", "fixed", "absent"]
    scenario_group: str


class Protocol(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    partition: Literal["development", "validation", "holdout"]
    frozen_before_run: bool
    contaminated: bool
    cases: list[Case]

    @model_validator(mode="after")
    def unique(self):
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate case identifiers")
        if len({(c.target, c.check_id, c.route) for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate measurements cannot inflate the sample")
        return self
