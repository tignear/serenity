(function() {
    var type_impls = Object.fromEntries([["serenity",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-CreateAttachment\" class=\"impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#impl-Clone-for-CreateAttachment\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h3><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#174\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","serenity::model::channel::AttachmentType"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-CreateAttachment\" class=\"impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#31-113\">source</a><a href=\"#impl-CreateAttachment\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.bytes\" class=\"method\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#33-40\">source</a><h4 class=\"code-header\">pub fn <a href=\"serenity/builder/struct.CreateAttachment.html#tymethod.bytes\" class=\"fn\">bytes</a>(\n    data: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt;&gt;,\n    filename: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt;,\n) -&gt; <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></summary><div class=\"docblock\"><p>Builds an <a href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\"><code>CreateAttachment</code></a> from the raw attachment data.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.path\" class=\"method\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#47-60\">source</a><h4 class=\"code-header\">pub async fn <a href=\"serenity/builder/struct.CreateAttachment.html#tymethod.path\" class=\"fn\">path</a>(path: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/path/struct.Path.html\" title=\"struct std::path::Path\">Path</a>&gt;) -&gt; <a class=\"type\" href=\"serenity/type.Result.html\" title=\"type serenity::Result\">Result</a>&lt;<a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a>&gt;</h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></summary><div class=\"docblock\"><p>Builds an <a href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\"><code>CreateAttachment</code></a> by reading a local file.</p>\n<h5 id=\"errors\"><a class=\"doc-anchor\" href=\"#errors\">§</a>Errors</h5>\n<p><a href=\"serenity/prelude/enum.SerenityError.html#variant.Io\" title=\"variant serenity::prelude::SerenityError::Io\"><code>Error::Io</code></a> if reading the file fails.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.file\" class=\"method\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#67-72\">source</a><h4 class=\"code-header\">pub async fn <a href=\"serenity/builder/struct.CreateAttachment.html#tymethod.file\" class=\"fn\">file</a>(\n    file: &amp;File,\n    filename: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt;,\n) -&gt; <a class=\"type\" href=\"serenity/type.Result.html\" title=\"type serenity::Result\">Result</a>&lt;<a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a>&gt;</h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></summary><div class=\"docblock\"><p>Builds an <a href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\"><code>CreateAttachment</code></a> by reading from a file handler.</p>\n<h5 id=\"errors-1\"><a class=\"doc-anchor\" href=\"#errors-1\">§</a>Errors</h5>\n<p><a href=\"serenity/prelude/enum.SerenityError.html#variant.Io\" title=\"variant serenity::prelude::SerenityError::Io\"><code>Error::Io</code></a> error if reading the file fails.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.url\" class=\"method\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#80-92\">source</a><h4 class=\"code-header\">pub async fn <a href=\"serenity/builder/struct.CreateAttachment.html#tymethod.url\" class=\"fn\">url</a>(http: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;<a class=\"struct\" href=\"serenity/http/struct.Http.html\" title=\"struct serenity::http::Http\">Http</a>&gt;, url: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.str.html\">str</a>) -&gt; <a class=\"type\" href=\"serenity/type.Result.html\" title=\"type serenity::Result\">Result</a>&lt;<a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a>&gt;</h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate features <code>builder</code> and <code>http</code></strong> only.</div></span></summary><div class=\"docblock\"><p>Builds an <a href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\"><code>CreateAttachment</code></a> by downloading attachment data from a URL.</p>\n<h5 id=\"errors-2\"><a class=\"doc-anchor\" href=\"#errors-2\">§</a>Errors</h5>\n<p><a href=\"serenity/prelude/enum.SerenityError.html#variant.Url\" title=\"variant serenity::prelude::SerenityError::Url\"><code>Error::Url</code></a> if the URL is invalid, <a href=\"serenity/prelude/enum.SerenityError.html#variant.Http\" title=\"variant serenity::prelude::SerenityError::Http\"><code>Error::Http</code></a> if downloading the data fails.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.to_base64\" class=\"method\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#99-106\">source</a><h4 class=\"code-header\">pub fn <a href=\"serenity/builder/struct.CreateAttachment.html#tymethod.to_base64\" class=\"fn\">to_base64</a>(&amp;self) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a></h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></summary><div class=\"docblock\"><p>Converts the stored data to the base64 representation.</p>\n<p>This is used in the library internally because Discord expects image data as base64 in many\nplaces.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.description\" class=\"method\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#109-112\">source</a><h4 class=\"code-header\">pub fn <a href=\"serenity/builder/struct.CreateAttachment.html#tymethod.description\" class=\"fn\">description</a>(self, description: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.Into.html\" title=\"trait core::convert::Into\">Into</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt;) -&gt; Self</h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></summary><div class=\"docblock\"><p>Sets a description for the file (max 1024 characters).</p>\n</div></details></div></details>",0,"serenity::model::channel::AttachmentType"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-CreateAttachment\" class=\"impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#impl-Debug-for-CreateAttachment\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h3><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/nightly/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","serenity::model::channel::AttachmentType"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-CreateAttachment\" class=\"impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#impl-PartialEq-for-CreateAttachment\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h3><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#261\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq","serenity::model::channel::AttachmentType"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-CreateAttachment\" class=\"impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#impl-Serialize-for-CreateAttachment\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.210/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h3><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.210/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.210/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.210/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.210/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.210/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","serenity::model::channel::AttachmentType"],["<section id=\"impl-StructuralPartialEq-for-CreateAttachment\" class=\"impl\"><a class=\"src rightside\" href=\"src/serenity/builder/create_attachment.rs.html#19\">source</a><a href=\"#impl-StructuralPartialEq-for-CreateAttachment\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"serenity/builder/struct.CreateAttachment.html\" title=\"struct serenity::builder::CreateAttachment\">CreateAttachment</a></h3><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>builder</code></strong> only.</div></span></section>","StructuralPartialEq","serenity::model::channel::AttachmentType"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[18868]}