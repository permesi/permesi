//! Rate limiting primitives for auth flows.

#[derive(Clone, Copy, Debug)]
pub enum RateLimitAction {
    Signup,
    Login,
    VerifyEmail,
    ResendVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited,
}

pub trait RateLimiter: Send + Sync {
    fn check_ip(&self, ip: Option<&str>, action: RateLimitAction) -> RateLimitDecision;
    fn check_email(&self, email: &str, action: RateLimitAction) -> RateLimitDecision;
}

#[derive(Clone, Debug)]
pub struct NoopRateLimiter;

impl RateLimiter for NoopRateLimiter {
    fn check_ip(&self, _ip: Option<&str>, _action: RateLimitAction) -> RateLimitDecision {
        RateLimitDecision::Allowed
    }

    fn check_email(&self, _email: &str, _action: RateLimitAction) -> RateLimitDecision {
        RateLimitDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_rate_limiter_allows() {
        let limiter = NoopRateLimiter;
        assert_eq!(
            limiter.check_ip(None, RateLimitAction::Signup),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_email("user@example.com", RateLimitAction::Login),
            RateLimitDecision::Allowed
        );
    }
}
