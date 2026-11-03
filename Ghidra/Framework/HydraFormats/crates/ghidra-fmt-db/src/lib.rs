//! Read path of `db.DBHandle`, `db.MasterTable`, `db.TableRecord`, `db.Table` and the
//! secondary index tables (`db.FieldIndexTable`).
//!
//! A [`Database`] owns a [`BufferStore`] (a saved `.gbf` as [`ghidra_fmt_gbf::BufferFile`], or an
//! in-memory store), reads the database parameters and the master table, and hands out
//! [`Table`] views. Tables are read through the B-tree family their schema selects.

use std::fmt;

use ghidra_fmt_btree::{BtreeError, NodeType, fieldkey::FieldKeyTree, longkey::LongKeyTree};
use ghidra_fmt_chain::{ChainError, DbParms};
use ghidra_fmt_field::{Field, FieldError, FieldType, IndexValue, Record, Schema};
use ghidra_fmt_gbf::{BufferStore, GbfError};

/// Database errors.
#[derive(Debug)]
pub enum DbError {
    /// Block file failure.
    Gbf(GbfError),
    /// Chained buffer / parameter failure.
    Chain(ChainError),
    /// B-tree failure.
    Btree(BtreeError),
    /// Field or schema failure.
    Field(FieldError),
    /// Structurally invalid database.
    Corrupt(String),
    /// No table with that name.
    TableNotFound(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gbf(e) => write!(f, "{e}"),
            Self::Chain(e) => write!(f, "{e}"),
            Self::Btree(e) => write!(f, "{e}"),
            Self::Field(e) => write!(f, "{e}"),
            Self::Corrupt(m) => write!(f, "corrupt database: {m}"),
            Self::TableNotFound(n) => write!(f, "table not found: {n}"),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gbf(e) => Some(e),
            Self::Chain(e) => Some(e),
            Self::Btree(e) => Some(e),
            Self::Field(e) => Some(e),
            _ => None,
        }
    }
}

macro_rules! from_err {
    ($t:ty, $v:ident) => {
        impl From<$t> for DbError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    };
}
from_err!(GbfError, Gbf);
from_err!(ChainError, Chain);
from_err!(BtreeError, Btree);
from_err!(FieldError, Field);

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, DbError>;

/// Column layout of a master table record (`TableRecord`).
pub fn master_schema() -> Schema {
    let fields = vec![
        FieldType::String,
        FieldType::Int,
        FieldType::Int,
        FieldType::Byte,
        FieldType::Binary,
        FieldType::String,
        FieldType::Int,
        FieldType::Long,
        FieldType::Int,
    ];
    let names = [
        "TableName",
        "SchemaVersion",
        "RootBufferId",
        "KeyType",
        "FieldTypes",
        "FieldNames",
        "IndexColumn",
        "MaxKey",
        "RecordCount",
    ]
    .map(str::to_owned)
    .to_vec();
    // `new Schema(0, "TableNum", fields, names)`: a long key, no sparse columns.
    match Schema::new(0, FieldType::Long, "TableNum", fields, names, &[]) {
        Ok(s) => s,
        Err(_) => unreachable!("static master schema is valid"),
    }
}

/// One master table row (`db.TableRecord`).
#[derive(Debug, Clone)]
pub struct TableRecord {
    /// Table number (master table key).
    pub table_num: i64,
    /// Table name; index tables carry the name of the table they index.
    pub name: String,
    /// Parsed schema.
    pub schema: Schema,
    /// Root buffer id, `-1` for a table that never stored a record.
    pub root_buffer_id: i32,
    /// Indexed column, `-1` for a primary table.
    pub indexed_column: i32,
    /// Largest long key ever used.
    pub max_key: i64,
    /// Record count.
    pub record_count: i32,
}

fn col_str(r: &Record, i: usize) -> Result<String> {
    match r.values.get(i) {
        Some(Some(Field::String(Some(s)))) => Ok(s.as_str().to_owned()),
        Some(Some(Field::String(None))) => Ok(String::new()),
        _ => Err(DbError::Corrupt(format!(
            "master column {i} is not a string"
        ))),
    }
}

fn col_int(r: &Record, i: usize) -> Result<i32> {
    match r.values.get(i) {
        Some(Some(Field::Int(v))) => Ok(*v),
        _ => Err(DbError::Corrupt(format!("master column {i} is not an int"))),
    }
}

impl TableRecord {
    fn from_record(store: &dyn BufferStore, r: &Record) -> Result<Self> {
        let table_num = r
            .key
            .long_value()
            .ok_or_else(|| DbError::Corrupt("master key is not a long".into()))?;
        let version = col_int(r, 1)?;
        let root = col_int(r, 2)?;
        let key_type = match r.values.get(3) {
            Some(Some(Field::Byte(v))) => *v as u8,
            _ => return Err(DbError::Corrupt("master key type column".into())),
        };
        let types: &[u8] = match r.values.get(4) {
            Some(Some(Field::Binary(Some(b)))) => b,
            Some(Some(Field::Binary(None))) => &[],
            _ => return Err(DbError::Corrupt("master field types column".into())),
        };
        let mut schema = Schema::from_encoded(version, key_type, types, &col_str(r, 5)?)?;
        force_var_key_nodes_if_needed(store, &mut schema, root)?;
        let max_key = match r.values.get(7) {
            Some(Some(Field::Long(v))) => *v,
            _ => return Err(DbError::Corrupt("master max key column".into())),
        };
        Ok(Self {
            table_num,
            name: col_str(r, 0)?,
            schema,
            root_buffer_id: root,
            indexed_column: col_int(r, 6)?,
            max_key,
            record_count: col_int(r, 8)?,
        })
    }
}

/// `TableRecord.forceUseOfVariableLengthKeyNodesIfNeeded`: a legacy table with a primitive
/// fixed-length key (other than long, index and fixed) may have been stored in var-key nodes.
fn force_var_key_nodes_if_needed(
    store: &dyn BufferStore,
    schema: &mut Schema,
    root: i32,
) -> Result<()> {
    if root < 0 {
        return Ok(());
    }
    let kt = schema.key_type();
    if kt.is_variable_length()
        || matches!(
            kt,
            FieldType::Long
                | FieldType::Index { .. }
                | FieldType::LegacyIndex { .. }
                | FieldType::Fixed10
        )
    {
        return Ok(());
    }
    let buf = store.get_buffer(root)?;
    let data = buf
        .data
        .as_deref()
        .ok_or_else(|| DbError::Corrupt(format!("table root buffer {root} is empty")))?;
    let t = data.first().copied().unwrap_or(0xff);
    if t == NodeType::VarKeyInterior as u8 || t == NodeType::VarKeyRec as u8 {
        schema.force_use_of_variable_length_key_nodes();
    }
    Ok(())
}

/// An open database.
pub struct Database<S: BufferStore> {
    store: S,
    params: DbParms,
    tables: Vec<TableRecord>,
}

impl<S: BufferStore> Database<S> {
    /// Open the database stored in `store` (`new DBHandle(bufferFile)`).
    pub fn open(store: S) -> Result<Self> {
        let params = DbParms::read(&store)?;
        let root = params.master_table_root()?;
        let schema = master_schema();
        let mut tables = Vec::new();
        if root >= 0 {
            let tree = LongKeyTree::new(&store, root, None);
            for rec in tree.records()? {
                let rec = rec?;
                let (r, _) = schema.read_record(Field::Long(rec.key), &rec.data, 0)?;
                tables.push(TableRecord::from_record(&store, &r)?);
            }
        }
        Ok(Self {
            store,
            params,
            tables,
        })
    }

    /// The underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Database id (`getDatabaseId`).
    pub fn database_id(&self) -> Result<i64> {
        Ok(self.params.database_id()?)
    }

    /// All master table rows, index tables included, ordered by table number.
    pub fn table_records(&self) -> &[TableRecord] {
        &self.tables
    }

    /// Primary tables, ordered by table number.
    pub fn tables(&self) -> impl Iterator<Item = Table<'_, S>> {
        self.tables
            .iter()
            .filter(|t| t.indexed_column == -1)
            .map(|record| Table { db: self, record })
    }

    /// Every table including index tables, ordered by table number.
    pub fn all_tables(&self) -> impl Iterator<Item = Table<'_, S>> {
        self.tables.iter().map(|record| Table { db: self, record })
    }

    /// Primary table by name (`getTable`).
    pub fn table(&self, name: &str) -> Result<Table<'_, S>> {
        self.tables()
            .find(|t| t.name() == name)
            .ok_or_else(|| DbError::TableNotFound(name.to_owned()))
    }

    /// Secondary index tables of `name`, ordered by table number.
    pub fn index_tables(&self, name: &str) -> Vec<Table<'_, S>> {
        self.tables
            .iter()
            .filter(|t| t.indexed_column >= 0 && t.name == name)
            .map(|record| Table { db: self, record })
            .collect()
    }
}

/// A table (primary or secondary index) of an open database.
pub struct Table<'a, S: BufferStore> {
    db: &'a Database<S>,
    record: &'a TableRecord,
}

impl<S: BufferStore> Clone for Table<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S: BufferStore> Copy for Table<'_, S> {}

/// Iterator over the decoded records of a table.
pub struct Records<'a> {
    inner: Box<dyn Iterator<Item = Result<Record>> + 'a>,
}

impl Iterator for Records<'_> {
    type Item = Result<Record>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<'a, S: BufferStore> Table<'a, S> {
    /// Master table row of this table.
    pub fn table_record(&self) -> &'a TableRecord {
        self.record
    }

    /// Table name.
    pub fn name(&self) -> &'a str {
        &self.record.name
    }

    /// Schema.
    pub fn schema(&self) -> &'a Schema {
        &self.record.schema
    }

    /// Record count as stored in the master table (`getRecordCount`).
    pub fn record_count(&self) -> i32 {
        self.record.record_count
    }

    /// Largest long key ever used (`getMaxKey`; `Long.MIN_VALUE` when none).
    pub fn max_key(&self) -> i64 {
        self.record.max_key
    }

    /// Indexed column of an index table, `-1` for a primary table.
    pub fn indexed_column(&self) -> i32 {
        self.record.indexed_column
    }

    fn fixed_len(&self) -> Option<usize> {
        let s = self.schema();
        (!s.is_variable_length()).then(|| s.fixed_length())
    }

    /// Iterate all records in key order (`Table.iterator`).
    pub fn records(&self) -> Result<Records<'a>> {
        let root = self.record.root_buffer_id;
        let schema = self.schema();
        if root < 0 {
            return Ok(Records {
                inner: Box::new(std::iter::empty()),
            });
        }
        let store = self.db.store();
        let fixed_len = self.fixed_len();
        if schema.use_long_key_nodes() {
            let tree = LongKeyTree::new(store, root, fixed_len);
            let it = tree.records()?.map(move |r| {
                let r = r?;
                let (rec, _) = schema.read_record(Field::Long(r.key), &r.data, 0)?;
                Ok(rec)
            });
            Ok(Records {
                inner: Box::new(it),
            })
        } else {
            let tree = FieldKeyTree::new(store, root, Some(schema.key_type().clone()), fixed_len);
            let it = tree.records()?.map(move |r| {
                let r = r?;
                let (rec, _) = schema.read_record(r.key, &r.data, 0)?;
                Ok(rec)
            });
            Ok(Records {
                inner: Box::new(it),
            })
        }
    }

    /// Record with primary key `key` (`getRecord`).
    pub fn get(&self, key: &Field) -> Result<Option<Record>> {
        let root = self.record.root_buffer_id;
        if root < 0 {
            return Ok(None);
        }
        let schema = self.schema();
        let store = self.db.store();
        let fixed_len = self.fixed_len();
        if schema.use_long_key_nodes() {
            let Some(k) = key.long_value() else {
                return Err(FieldError::TypeMismatch.into());
            };
            match LongKeyTree::new(store, root, fixed_len).get(k)? {
                Some(r) => Ok(Some(schema.read_record(Field::Long(r.key), &r.data, 0)?.0)),
                None => Ok(None),
            }
        } else {
            let tree = FieldKeyTree::new(store, root, Some(schema.key_type().clone()), fixed_len);
            match tree.get(key)? {
                Some(r) => Ok(Some(schema.read_record(r.key, &r.data, 0)?.0)),
                None => Ok(None),
            }
        }
    }

    /// Entries of an index table in key order: indexed value and primary key.
    pub fn index_entries(&self) -> Result<Vec<IndexValue>> {
        if self.record.indexed_column < 0 {
            return Err(DbError::Corrupt(format!(
                "{} is not an index table",
                self.name()
            )));
        }
        let mut out = Vec::new();
        for r in self.records()? {
            match r?.key {
                Field::Index(v) => out.push(*v),
                _ => {
                    return Err(DbError::Corrupt(
                        "index table key is not an index field".into(),
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Primary keys of the records of this primary table whose column `column` equals `value`,
    /// found through the secondary index (`None` when `column` has no index table).
    pub fn find_primary_keys(&self, column: usize, value: &Field) -> Result<Option<Vec<Field>>> {
        let Some(index) = self
            .db
            .index_tables(self.name())
            .into_iter()
            .find(|t| t.indexed_column() as usize == column)
        else {
            return Ok(None);
        };
        let mut keys = Vec::new();
        for e in index.index_entries()? {
            // stored values may be truncated: compare after forming the key the same way
            let probe = Field::new_index(value.clone(), e.primary.clone(), e.legacy)?;
            if let Field::Index(p) = probe
                && p.indexed.compare(&e.indexed)?.is_eq()
            {
                keys.push(e.primary);
            }
        }
        Ok(Some(keys))
    }
}

#[cfg(test)]
mod tests;
