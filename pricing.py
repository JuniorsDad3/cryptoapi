from datetime import datetime, timedelta

class PricingCalculator:
    def __init__(self):
        self.tiers = {
            'starter': {
                'name': 'Starter',
                'monthly_price': 29,
                'storage_gb': 50,
                'users': 3,
                'api_calls': 500,
                'support': 'Email',
                'features': ['Basic Encryption', 'Standard Support']
            },
            'professional': {
                'name': 'Professional', 
                'monthly_price': 99,
                'storage_gb': 250,
                'users': 10,
                'api_calls': 5000,
                'support': 'Priority Email',
                'features': ['Advanced Encryption', 'Priority Support', 'API Access']
            },
            'enterprise': {
                'name': 'Enterprise',
                'monthly_price': 299,
                'storage_gb': 1000,
                'users': 50,
                'api_calls': 50000,
                'support': '24/7 Phone',
                'features': ['Military-Grade Encryption', 'Dedicated Support', 'Custom SLA']
            }
        }
    
    def get_pricing_tiers(self):
        return self.tiers
    
    def calculate_usage_cost(self, storage_gb, api_calls, tier):
        """Calculate costs based on usage"""
        tier_info = self.tiers.get(tier, self.tiers['starter'])
        
        # Base price
        cost = tier_info['monthly_price']
        
        # Overage calculations
        storage_overage = max(0, storage_gb - tier_info['storage_gb'])
        storage_cost = storage_overage * 0.15  # $0.15/GB overage
        
        api_overage = max(0, api_calls - tier_info['api_calls']) 
        api_cost = api_overage * 0.02  # $0.02/API call overage
        
        total = cost + storage_cost + api_cost
        return {
            'base_price': cost,
            'storage_overage': storage_cost,
            'api_overage': api_cost,
            'total': total
        }

class BillingManager:
    def __init__(self):
        self.usage_data = {}
    
    def create_account(self, user_id, tier):
        """Initialize billing account"""
        self.usage_data[user_id] = {
            'tier': tier,
            'storage_used_gb': 0,
            'api_calls_used': 0,
            'created_date': datetime.utcnow(),
            'last_billing_date': datetime.utcnow()
        }
    
    def track_usage(self, user_id, usage_type, amount):
        """Track user usage for billing"""
        if user_id in self.usage_data:
            if usage_type == 'storage':
                self.usage_data[user_id]['storage_used_gb'] += amount / (1024**3)  # Convert to GB
            elif usage_type == 'upload':
                self.usage_data[user_id]['api_calls_used'] += amount
            elif usage_type == 'download':
                self.usage_data[user_id]['api_calls_used'] += amount
    
    def get_usage_stats(self, user_id):
        """Get current usage statistics"""
        if user_id not in self.usage_data:
            return {}
        
        data = self.usage_data[user_id]
        calculator = PricingCalculator()
        tier_info = calculator.tiers.get(data['tier'], calculator.tiers['starter'])
        
        return {
            'storage_used_gb': round(data['storage_used_gb'], 2),
            'storage_limit_gb': tier_info['storage_gb'],
            'api_calls_used': data['api_calls_used'],
            'api_calls_limit': tier_info['api_calls'],
            'storage_percentage': round((data['storage_used_gb'] / tier_info['storage_gb']) * 100, 1),
            'api_percentage': round((data['api_calls_used'] / tier_info['api_calls']) * 100, 1)
        }
    
    def get_billing_info(self, user_id):
        """Get billing information"""
        if user_id not in self.usage_data:
            return {}
        
        data = self.usage_data[user_id]
        calculator = PricingCalculator()
        cost_breakdown = calculator.calculate_usage_cost(
            data['storage_used_gb'], data['api_calls_used'], data['tier']
        )
        
        return {
            'current_tier': data['tier'],
            'next_billing_date': (data['last_billing_date'] + timedelta(days=30)).strftime('%Y-%m-%d'),
            'cost_breakdown': cost_breakdown
        }
    
    def get_invoice_history(self, user_id):
        """Get invoice history"""
        # Implementation would fetch from database
        return []

# Create global instances
billing_mgr = BillingManager()
pricing_calculator = PricingCalculator()
