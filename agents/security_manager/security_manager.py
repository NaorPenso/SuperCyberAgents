"""Security Manager - Orchestrates security tasks and delegates to specialized agents."""

import json
import logging
from typing import Any, Dict, List

from pydantic import BaseModel, Field, ValidationError

from agents import register_agent
from agents.base import AgentConfig, BaseAgent
from core.initialization import get_all_agents  # Import to get available agents
from core.llm_clients import get_llm_client
from schemas.delegate_task_schemas import DelegateTaskInput, DelegateTaskOutput
from schemas.security_manager_schemas import (
    DelegatedTaskResult,
    SecurityManagerInput,
    SecurityManagerOutput,
)
from tools.base import BaseTool

logger = logging.getLogger(__name__)

# --- Structures for LLM Interaction --- #


class DelegationPlan(BaseModel):
    """Defines a single task delegation within the security plan."""

    agent_id: str = Field(..., description="The ID of the agent to delegate to.")
    agent_input: Dict[str, Any] = Field(
        ..., description="The specific input dictionary for the target agent."
    )


class SecurityPlan(BaseModel):
    """Represents the overall plan created by the LLM."""

    delegations: List[DelegationPlan] = Field(
        ..., description="List of tasks to delegate."
    )


# --- Security Manager Implementation --- #


@register_agent(name="security_manager")
class SecurityManager(BaseAgent[SecurityManagerInput, SecurityManagerOutput]):
    """Orchestrates security tasks by planning and delegating to other agents."""

    input_schema = SecurityManagerInput
    output_schema = SecurityManagerOutput

    # Store available agent info for planning prompt
    _available_agents_info: str = ""

    def __init__(self, config: AgentConfig, tools: List[BaseTool]):
        super().__init__(config, tools)
        try:
            self.llm_client = get_llm_client(config.llm_provider)
        except ValueError as e:
            logger.error(
                f"Failed to get LLM client for provider '{config.llm_provider}': {e}"
            )
            raise
        logger.info(f"SecurityManager initialized with ID: {self.config.id}")

    def _prepare_available_agents_info(self):
        """Creates a string listing available agents for the LLM planning prompt."""
        # Exclude the manager itself from the list of delegates
        available_delegate_agents = {
            agent_id: agent
            for agent_id, agent in get_all_agents().items()
            if agent_id != self.config.id
        }

        available_agents_info = "\nAvailable Delegate Agents:\n"
        if not available_delegate_agents:
            available_agents_info += "- None\n"
        else:
            for agent_id, agent_instance in available_delegate_agents.items():
                # Include ID, description, and maybe input schema for context
                input_schema_name = agent_instance.config.input_schema
                available_agents_info += f"- ID: {agent_id}\n  Description: {agent_instance.config.description}\n  Input Schema: {input_schema_name}\n"
        self._available_agents_info = available_agents_info
        logger.debug(f"Prepared available agents info:\n{self._available_agents_info}")

    def _generate_plan(self, task_description: str) -> SecurityPlan | None:
        """Uses the LLM to generate an execution plan."""
        prompt = f"""
        You are a security operations manager.
        Your task is to analyze the user's request and create an execution plan involving calling other specialized agents.

        Here are the available agents you can delegate tasks to:
        {self._available_agents_info}

        The user's request is: {task_description}

        Based ONLY on the available agents listed above, determine the sequence of agent delegations needed to fulfill the request.
        For each delegation, specify the 'agent_id' (MUST be one of the IDs listed above) and the 'agent_input' (a JSON object matching the agent's Input Schema).
        Do NOT invent agent IDs or capabilities.
        If the request cannot be fulfilled with the available agents, state that clearly.

        Respond ONLY with a JSON object matching the following Pydantic schema:

        ```json
        {{{{
            "delegations": [
                {{
                    "agent_id": "string (must match an available agent ID)",
                    "agent_input": {{ "field_name": "value", ... }} // EXACT keys/values required by schema
                }}
                // ... more delegations if needed
            ]
        }}}}
        ```

        If the task cannot be fulfilled with the available agents, respond with:
        ```json
        {{ "delegations": [] }}
        ```

        JSON Response:
        """

        try:
            logger.info("Generating execution plan using LLM...")
            response_text = self.llm_client.generate(
                prompt=prompt, model=self.model_name
            )
            logger.debug(f"LLM plan generation response: {response_text}")

            # Clean potential markdown code fences
            if response_text.strip().startswith("```json"):
                response_text = response_text.strip()[7:-3].strip()
            elif response_text.strip().startswith("```"):
                response_text = response_text.strip()[3:-3].strip()

            plan_dict = json.loads(response_text)
            plan = SecurityPlan(**plan_dict)
            if not plan.delegations:
                logger.warning("LLM generated an empty delegation plan.")
                return None  # Indicate no plan or task cannot be fulfilled

            logger.info(f"LLM generated execution plan: {plan}")
            return plan

        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to decode LLM plan response as JSON: {e}\nResponse: {response_text}"
            )
            return None
        except ValidationError as e:
            logger.error(
                f"LLM plan response failed validation: {e}\nResponse: {response_text}"
            )
            return None
        except Exception as e:
            logger.exception(f"Error during LLM plan generation: {e}")
            return None

    def _summarize_results(
        self, task_description: str, results: List[DelegatedTaskResult]
    ) -> str:
        """Uses the LLM to summarize the results of delegated tasks."""
        results_str = "\n".join(
            [
                f"- Agent: {r.agent_id}, Status: {r.status}, Output: {r.result or r.error_message}"
                for r in results
            ]
        )

        prompt = f"""
        The following task was executed: "{task_description}"

        The following steps were taken by delegating to specialized agents:
        {results_str}

        Based on these results, provide a concise summary of the findings for the original task.
        Focus on answering the original request and highlight any important outcomes or errors.

        Summary:
        """

        try:
            logger.info("Generating summary using LLM...")
            summary = self.llm_client.generate(prompt=prompt, model=self.model_name)
            logger.info("LLM generated final summary.")
            return summary.strip()
        except Exception as e:
            logger.exception(f"Error during LLM result summarization: {e}")
            return f"Failed to generate summary due to an error: {e}"

    def run(self, input_data: SecurityManagerInput) -> SecurityManagerOutput:
        # Prepare available agents info now that system is initialized
        self._prepare_available_agents_info()
        logger.info(f"SecurityManager received task: {input_data.task_description}")

        # --- Step 1: Planning Phase --- #
        security_plan = self._generate_plan(input_data.task_description)

        if security_plan is None:
            # Handle cases where planning failed or returned empty
            error_msg = "Failed to generate a valid execution plan for the task."
            logger.error(error_msg)
            return SecurityManagerOutput(
                summary="Planning Failed",
                delegated_results=[],
                error=error_msg,
                status="error",
            )
        elif not security_plan.delegations:
            summary_msg = "The task could not be fulfilled with the available agents or requires no delegation."
            logger.warning(summary_msg)
            return SecurityManagerOutput(
                summary=summary_msg, delegated_results=[], error=None, status="success"
            )

        # --- Step 2: Delegation Phase --- #
        delegate_tool_alias = "delegate_task"  # Must match alias in config
        if delegate_tool_alias not in self.tools:
            error_msg = f"Required tool '{delegate_tool_alias}' not found in agent configuration."
            logger.error(error_msg)
            return SecurityManagerOutput(
                summary="Configuration error.",
                delegated_results=[],
                error=error_msg,
                status="error",
            )

        delegate_tool = self.tools[delegate_tool_alias]
        all_results: List[DelegatedTaskResult] = []

        for delegation in security_plan.delegations:
            logger.info(
                f"Delegating to {delegation.agent_id} with input: {delegation.agent_input}"
            )
            try:
                tool_input = DelegateTaskInput(
                    agent_id=delegation.agent_id, agent_input=delegation.agent_input
                )
                # Execute the delegation tool
                delegation_output: DelegateTaskOutput = delegate_tool.execute(
                    tool_input
                )

                # Convert tool output to DelegatedTaskResult schema
                task_result = DelegatedTaskResult(
                    agent_id=delegation_output.agent_id,
                    status=delegation_output.status,
                    result=delegation_output.result,
                    error_message=delegation_output.error_message,
                )
                all_results.append(task_result)

                if task_result.status == "error":
                    logger.error(
                        f"Delegation to {delegation.agent_id} failed: {task_result.error_message}"
                    )
                else:
                    logger.info(f"Delegation to {delegation.agent_id} succeeded.")

            except Exception as e:
                # Catch errors in preparing/calling the tool itself
                error_msg = (
                    f"Error during delegation attempt to {delegation.agent_id}: {e}"
                )
                logger.exception(error_msg)
                all_results.append(
                    DelegatedTaskResult(
                        agent_id=delegation.agent_id,
                        status="error",
                        error_message=error_msg,
                    )
                )

        # --- Step 3: Summarization Phase --- #
        final_summary = self._summarize_results(
            input_data.task_description, all_results
        )

        # Determine overall error status
        overall_error = None
        if any(r.status == "error" for r in all_results):
            overall_error = "One or more delegated tasks failed. Check delegated_results for details."
            # Could potentially refine this error based on the summary

        return SecurityManagerOutput(
            summary=final_summary, delegated_results=all_results, error=overall_error
        )
