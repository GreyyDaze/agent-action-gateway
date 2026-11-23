"""A scripted agent used to demonstrate the quickstart."""
from agent_action_gateway.integrations.adapters.mock import MockProvider


def make_refund_agent(provider: MockProvider):
    def agent(task: str) -> dict[str, object]:
        customer = task.split("for ", 1)[-1].strip("?. ") if "for " in task else "Ava"
        order = provider.lookup_order(customer)
        if order is None:
            return {"status": "not_found", "customer": customer}
        return {
            "status": "refunded",
            "order_id": order.order_id,
            "result": provider.refund(order.order_id),
        }

    return agent
