"""
Orders Blueprint routes for Mock Shop App.
Demonstrates cross-file Blueprint routing + 2-hop service helper call chains.
"""

import sqlite3
from flask import Blueprint, request
from services.order_service import fetch_order_by_id, fetch_order_safe_parameterized

orders_bp = Blueprint("orders", __name__)


@orders_bp.route("/orders", methods=["GET"])
def get_orders():
    order_id = request.args.get("id", "1")
    # Calls 1-hop helper in services/order_service.py which executes vulnerable SQL
    return fetch_order_by_id(order_id)


@orders_bp.route("/orders/safe", methods=["GET"])
def get_orders_safe():
    order_id = request.args.get("id", "1")
    # Calls safe parameterized query helper (Safe Decoy 8)
    return fetch_order_safe_parameterized(order_id)
