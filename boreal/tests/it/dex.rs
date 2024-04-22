use boreal::module::Dex;

use crate::libyara_compat::util::DEX_FILE;
use crate::utils::compare_module_values_on_mem;

#[test]
fn test_coverage_constants() {
    let diffs = [];
    compare_module_values_on_mem(Dex, "DEX_FILE", DEX_FILE, false, &diffs);
    compare_module_values_on_mem(Dex, "DEX_FILE", DEX_FILE, true, &diffs);
}
