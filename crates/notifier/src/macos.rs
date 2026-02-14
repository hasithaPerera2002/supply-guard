use notify_rust::Notification;
use shared::{NotificationError, Severity, ThreatResult};
use tracing::{error, info};

pub struct MacOSNotifier {
    enabled: bool,
    min_severity: Severity,
}

impl MacOSNotifier {
    pub fn new(enabled: bool, min_severity: Severity) -> Self {
        Self {
            enabled,
            min_severity,
        }
    }

    pub async fn notify_threat(&self, threat: &ThreatResult) -> Result<(), NotificationError> {
        if !self.enabled {
            return Ok(());
        }

        if threat.severity < self.min_severity {
            return Ok(());
        }

        let (title, body, sound) = match threat.severity {
            Severity::Critical => (
                "⚠️ Supply Chain Threat - CRITICAL",
                format!(
                    "{} detected in {}\n{}",
                    threat.threat_type.as_str(),
                    threat.file_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown"),
                    threat.context
                ),
                Some("Basso"), // System alert sound
            ),
            Severity::High => (
                "🔍 Suspicious Code Detected",
                format!(
                    "{} in {}\n{}",
                    threat.threat_type.as_str(),
                    threat.file_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown"),
                    threat.context
                ),
                None,
            ),
            Severity::Medium => (
                "🔍 Suspicious Code Detected",
                format!(
                    "{} in {}",
                    threat.threat_type.as_str(),
                    threat.file_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                ),
                None,
            ),
            Severity::Low => {
                // Low severity threats are logged only
                info!("Low severity threat: {} in {}", threat.threat_type.as_str(), threat.file_path.display());
                return Ok(());
            }
        };

        let mut notification = Notification::new()
            .summary(&title)
            .body(&body)
            .appname("SupplyGuard")
            .timeout(notify_rust::Timeout::Never);

        if let Some(sound_name) = sound {
            notification = notification.sound_name(sound_name);
        }

        match notification.show() {
            Ok(_) => {
                info!("Notification sent for threat: {} in {}", threat.threat_type.as_str(), threat.file_path.display());
                Ok(())
            }
            Err(e) => {
                error!("Failed to send notification: {}", e);
                Err(NotificationError::SendError(format!("{}", e)))
            }
        }
    }
}
