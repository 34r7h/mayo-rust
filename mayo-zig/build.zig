const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Native Static Library ---
    const lib_native = b.addStaticLibrary(.{
        .name = "mayo_native",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add all .zig files from src to the native library.
    // This is a simple way for now; more advanced builds might selectively add files.
    // Note: This assumes all .zig files in src/ are part of the library.
    // If some are not (e.g. main.zig for an executable), this would need adjustment.
    const main_module = b.addModule("main", .{ .root_source_file = b.path("src/lib.zig") });
    lib_native.root_module.addImport("main", main_module);
    // A more direct way for simple libraries is often to let `lib.zig` import other files,
    // and those imports will be resolved by the compiler.
    // For now, `lib.zig` will be the entry point that pulls in other modules.

    b.installArtifact(lib_native);

    // --- WASM32 Shared Library ---
    const lib_wasm = b.addStaticLibrary(.{
        .name = "mayo_wasm",
        .root_source_file = b.path("src/lib.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
        }),
        .optimize = optimize,
    });
    // Similar to native, ensure wasm target can find modules via lib.zig
    // lib_wasm.addPackagePath("main", "src/lib.zig"); // If needed, usually not for wasm if lib.zig handles imports

    b.installArtifact(lib_wasm);

    // --- Standard Run Step for Native (Optional) ---
    // If you had an executable defined using src/main.zig, you could add a run step:
    // const exe = b.addExecutable(.{...});
    // const run_cmd = b.addRunArtifact(exe);
    // ...
    // const run_step = b.step("run", "Run the app");
    // run_step.dependOn(&run_cmd.step);

    // --- Standard Test Step ---
    // This will test code linked into the native library.
    // To test WASM, a different approach (e.g. Node.js runner) would be needed.
    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"), // Assuming tests are accessible from lib.zig
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run library tests");
    const run_main_tests = b.addRunArtifact(main_tests);
    test_step.dependOn(&run_main_tests.step);

    // --- KAT Test Step ---
    const kat_tests = b.addTest(.{
        .root_source_file = b.path("test/kat_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Define the src module, using lib.zig as the root file
    const src_module = b.addModule("src", .{ .root_source_file = b.path("src/lib.zig") });

    // Add the src module as an import named "src" to the KAT test's root module
    // This makes components imported/declared in src/lib.zig available via `@import("src")`
    kat_tests.root_module.addImport("src", src_module);

    const run_kat_tests = b.addRunArtifact(kat_tests);
    test_step.dependOn(&run_kat_tests.step);
}
