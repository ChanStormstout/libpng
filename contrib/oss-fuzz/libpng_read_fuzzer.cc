#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <png.h>

// Function prototypes for classified functions
void png_init_io(png_structp png_ptr, FILE *fp);
void png_read_png(png_structrp png_ptr, png_inforp info_ptr, int transforms, png_voidp params);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Initializer: Create png_struct and png_info
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL) {
        return 0;
    }
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    // Data Entrypoint: Initialize IO (using memory for simplicity)
    std::vector<uint8_t> png_data = stream.ConsumeRemainingBytes<uint8_t>();
    png_set_read_fn(png_ptr, static_cast<void*>(png_data.data()), [](png_structp png_ptr, png_bytep data, png_size_t length) {
        auto& io_ptr = *static_cast<std::vector<uint8_t>*>(png_get_io_ptr(png_ptr));
        if (io_ptr.size() < length) {
            png_error(png_ptr, "Read error");
        }
        memcpy(data, io_ptr.data(), length);
        io_ptr.erase(io_ptr.begin(), io_ptr.begin() + length);
    });

    // Data Entrypoint: Read the PNG info
    png_read_info(png_ptr, info_ptr);

    // Data Processor: Read the entire PNG image
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

    // Data Processor: Update info after transformations
    png_read_update_info(png_ptr, info_ptr);

    // Data Processor: Get row bytes
    png_uint_32 row_bytes = png_get_rowbytes(png_ptr, info_ptr);

    // Data Processor: Allocate memory for a row and read a row
    png_bytep row = static_cast<png_bytep>(png_malloc(png_ptr, row_bytes));
    if (row == NULL) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }
    png_read_row(png_ptr, row, NULL);

    // Auxiliary Function: Free the allocated row memory
    png_free(png_ptr, row);

    // Cleanup
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);

    return 0;
}
