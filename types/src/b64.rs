use base64::prelude::*;
use serde::{
    Deserializer, Serializer,
    de::{self, Unexpected, Visitor},
};
use std::fmt;

pub fn serialize<S: Serializer>(data: &impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64_STANDARD.encode(data.as_ref()))
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Base64Visitor;
    impl Visitor<'_> for Base64Visitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a base64-encoded string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            BASE64_STANDARD
                .decode(v)
                .map_err(|_| E::invalid_value(Unexpected::Str(v), &self))
        }
    }
    deserializer.deserialize_str(Base64Visitor)
}

pub mod list {
    use serde::{
        Deserialize, Deserializer, Serialize, Serializer,
        de::{SeqAccess, Visitor},
        ser::SerializeSeq,
    };
    use std::fmt;

    pub fn serialize<T: AsRef<[u8]>, S: Serializer>(
        data: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for elem in data {
            #[derive(Serialize)]
            #[serde(transparent)]
            struct Elem<T: AsRef<[u8]>>(#[serde(with = "super")] T);
            seq.serialize_element(&Elem(elem))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        struct VecBase64Visitor;
        impl<'de> Visitor<'de> for VecBase64Visitor {
            type Value = Vec<Vec<u8>>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a list of base64-encoded strings")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                #[derive(Deserialize)]
                #[serde(transparent)]
                struct Elem(#[serde(with = "super")] Vec<u8>);
                let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(8));
                while let Some(elem) = seq.next_element::<Elem>()? {
                    vec.push(elem.0);
                }
                Ok(vec)
            }
        }
        deserializer.deserialize_seq(VecBase64Visitor)
    }
}
