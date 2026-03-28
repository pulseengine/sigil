//! WASM Component Model section types (informational).
//!
//! The component binary format uses section IDs in the same range as
//! core modules but with different semantics. The core parser handles
//! these via `SectionId::Extension(u8)` which is sufficient for signing
//! since the hash covers all bytes regardless of section type.

/// Component model section IDs per the WASM Component Model binary spec.
/// These are not used in the signing path (`Extension(u8)` handles them)
/// but are documented here for reference and future validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComponentSectionId {
    Custom = 0x00,
    CoreModule = 0x01,
    CoreInstance = 0x02,
    CoreType = 0x03,
    Component = 0x04,
    Instance = 0x05,
    Alias = 0x06,
    Type = 0x07,
    Canon = 0x08,
    Start = 0x09,
    Import = 0x0A,
    Export = 0x0B,
}

impl ComponentSectionId {
    pub fn from_u8(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(Self::Custom),
            0x01 => Some(Self::CoreModule),
            0x02 => Some(Self::CoreInstance),
            0x03 => Some(Self::CoreType),
            0x04 => Some(Self::Component),
            0x05 => Some(Self::Instance),
            0x06 => Some(Self::Alias),
            0x07 => Some(Self::Type),
            0x08 => Some(Self::Canon),
            0x09 => Some(Self::Start),
            0x0A => Some(Self::Import),
            0x0B => Some(Self::Export),
            _ => None,
        }
    }

    pub fn is_nested(&self) -> bool {
        matches!(self, Self::CoreModule | Self::Component)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_section_ids() {
        assert_eq!(
            ComponentSectionId::from_u8(0x01),
            Some(ComponentSectionId::CoreModule)
        );
        assert_eq!(
            ComponentSectionId::from_u8(0x04),
            Some(ComponentSectionId::Component)
        );
        assert_eq!(ComponentSectionId::from_u8(0xFF), None);
    }

    #[test]
    fn test_nested_detection() {
        assert!(ComponentSectionId::CoreModule.is_nested());
        assert!(ComponentSectionId::Component.is_nested());
        assert!(!ComponentSectionId::Export.is_nested());
    }
}
