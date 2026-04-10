// Strict encoding library for deterministic binary serialization.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright (C) 2019-2022 LNP/BP Standards Association.
// Copyright (C) 2022-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use std::any;
use std::collections::BTreeSet;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;

use crate::{LibName, TypeName, VariantName};

pub fn type_name<T>() -> String {
    let name = any::type_name::<T>();
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len());

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'&' || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
            continue;
        }
        if matches!(b, b',' | b'<' | b'>' | b'(' | b')') {
            i += 1;
            continue;
        }

        let start = i;
        while i < bytes.len()
            && !matches!(
                bytes[i],
                b'&' | b' ' | b'\t' | b'\n' | b'\r' | b',' | b'<' | b'>' | b'(' | b')'
            )
        {
            i += 1;
        }

        // Manual scan from the end to find the last ':' — avoids TwoWaySearcher
        let token_bytes = &bytes[start..i];
        let ident_start = token_bytes
            .iter()
            .rposition(|&b| b == b':')
            .map(|p| start + p + 1)
            .unwrap_or(start);
        // SAFETY: token is a sub-slice of `name` which is a valid &str; ident_start is always
        // on a char boundary since ':' is ASCII.
        out.push_str(&name[ident_start..i]);
    }

    out
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("unexpected variant {1} for enum or union {0:?}")]
pub struct VariantError<V: Debug + Display>(pub Option<String>, pub V);

impl<V: Debug + Display> VariantError<V> {
    pub fn with<T>(val: V) -> Self {
        VariantError(Some(type_name::<T>()), val)
    }
    pub fn typed(name: impl Into<String>, val: V) -> Self {
        VariantError(Some(name.into()), val)
    }
    pub fn untyped(val: V) -> Self {
        VariantError(None, val)
    }
}

pub trait StrictDumb: Sized {
    fn strict_dumb() -> Self;
}

impl<T> StrictDumb for T
where
    T: StrictType + Default,
{
    fn strict_dumb() -> T {
        T::default()
    }
}

pub trait StrictType: Sized {
    const STRICT_LIB_NAME: &'static str;
    fn strict_name() -> Option<TypeName> {
        Some(tn!(type_name::<Self>()))
    }
}

impl<T: StrictType> StrictType for &T {
    const STRICT_LIB_NAME: &'static str = T::STRICT_LIB_NAME;
}

impl<T> StrictType for PhantomData<T> {
    const STRICT_LIB_NAME: &'static str = "";
}

pub trait StrictProduct: StrictType + StrictDumb {}

pub trait StrictTuple: StrictProduct {
    const FIELD_COUNT: u8;
    fn strict_check_fields() {
        let name = Self::strict_name().unwrap_or_else(|| tn!("__unnamed"));
        assert_ne!(
            Self::FIELD_COUNT,
            0,
            "tuple type {} does not contain a single field defined",
            name
        );
    }

    fn strict_type_info() -> TypeInfo<Self> {
        Self::strict_check_fields();
        TypeInfo {
            lib: libname!(Self::STRICT_LIB_NAME),
            name: Self::strict_name().map(|name| tn!(name)),
            cls: TypeClass::Tuple(Self::FIELD_COUNT),
            dumb: Self::strict_dumb(),
        }
    }
}

pub trait StrictStruct: StrictProduct {
    const ALL_FIELDS: &'static [&'static str];

    fn strict_check_fields() {
        let name = Self::strict_name().unwrap_or_else(|| tn!("__unnamed"));
        assert!(
            !Self::ALL_FIELDS.is_empty(),
            "struct type {} does not contain a single field defined",
            name
        );
        let names: BTreeSet<_> = Self::ALL_FIELDS.iter().copied().collect();
        assert_eq!(
            names.len(),
            Self::ALL_FIELDS.len(),
            "struct type {} contains repeated field names",
            name
        );
    }

    fn strict_type_info() -> TypeInfo<Self> {
        Self::strict_check_fields();
        TypeInfo {
            lib: libname!(Self::STRICT_LIB_NAME),
            name: Self::strict_name().map(|name| tn!(name)),
            cls: TypeClass::Struct(Self::ALL_FIELDS),
            dumb: Self::strict_dumb(),
        }
    }
}

pub trait StrictSum: StrictType {
    const ALL_VARIANTS: &'static [(u8, &'static str)];

    fn strict_check_variants() {
        let name = Self::strict_name().unwrap_or_else(|| tn!("__unnamed"));
        assert!(
            !Self::ALL_VARIANTS.is_empty(),
            "type {} does not contain a single variant defined",
            name
        );
        let (ords, names): (BTreeSet<_>, BTreeSet<_>) = Self::ALL_VARIANTS.iter().copied().unzip();
        assert_eq!(
            ords.len(),
            Self::ALL_VARIANTS.len(),
            "type {} contains repeated variant ids",
            name
        );
        assert_eq!(
            names.len(),
            Self::ALL_VARIANTS.len(),
            "type {} contains repeated variant names",
            name
        );
    }

    fn variant_name_by_tag(tag: u8) -> Option<VariantName> {
        Self::ALL_VARIANTS
            .iter()
            .find(|(n, _)| *n == tag)
            .map(|(_, variant_name)| vname!(*variant_name))
    }

    fn variant_ord(&self) -> u8 {
        let variant = self.variant_name();
        for (tag, name) in Self::ALL_VARIANTS {
            if *name == variant {
                return *tag;
            }
        }
        unreachable!(
            "not all variants are enumerated for {} enum in StrictUnion::all_variants \
             implementation",
            type_name::<Self>()
        )
    }
    fn variant_name(&self) -> &'static str;
}

pub trait StrictUnion: StrictSum + StrictDumb {
    fn strict_type_info() -> TypeInfo<Self> {
        Self::strict_check_variants();
        TypeInfo {
            lib: libname!(Self::STRICT_LIB_NAME),
            name: Self::strict_name().map(|name| tn!(name)),
            cls: TypeClass::Union(Self::ALL_VARIANTS),
            dumb: Self::strict_dumb(),
        }
    }
}

pub trait StrictEnum
where
    Self: StrictSum + Copy + TryFrom<u8, Error = VariantError<u8>>,
    u8: From<Self>,
{
    fn from_variant_name(name: &VariantName) -> Result<Self, VariantError<&VariantName>> {
        for (tag, n) in Self::ALL_VARIANTS {
            if *n == name.as_str() {
                return Self::try_from(*tag).map_err(|_| VariantError::with::<Self>(name));
            }
        }
        Err(VariantError::with::<Self>(name))
    }

    fn strict_type_info() -> TypeInfo<Self> {
        Self::strict_check_variants();
        TypeInfo {
            lib: libname!(Self::STRICT_LIB_NAME),
            name: Self::strict_name().map(|name| tn!(name)),
            cls: TypeClass::Enum(Self::ALL_VARIANTS),
            dumb: Self::try_from(Self::ALL_VARIANTS[0].0)
                .expect("first variant contains invalid value"),
        }
    }
}

pub enum TypeClass {
    Embedded,
    Enum(&'static [(u8, &'static str)]),
    Union(&'static [(u8, &'static str)]),
    Tuple(u8),
    Struct(&'static [&'static str]),
}

pub struct TypeInfo<T: StrictType> {
    pub lib: LibName,
    pub name: Option<TypeName>,
    pub cls: TypeClass,
    pub dumb: T,
}

#[cfg(test)]
mod test {
    use amplify::confinement::TinyVec;

    use super::*;

    #[test]
    fn name_derivation() {
        assert_eq!(Option::<TinyVec<u8>>::strict_name(), None)
    }
}
