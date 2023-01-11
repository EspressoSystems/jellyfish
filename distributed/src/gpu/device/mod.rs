use once_cell::sync::Lazy;
use rustacuda::error::CudaResult;

pub struct CudaContexts(Vec<rustacuda::context::Context>);

unsafe impl Send for CudaContexts {}
unsafe impl Sync for CudaContexts {}

pub fn build_device_list() -> CudaResult<(Vec<Device>, CudaContexts)> {
    let mut all_devices = Vec::new();
    let mut contexts = Vec::new();

    rustacuda::init(rustacuda::CudaFlags::empty())?;
    for device in rustacuda::device::Device::devices()? {
        let device = device?;
        let owned_context = rustacuda::context::Context::create_and_push(
            rustacuda::context::ContextFlags::MAP_HOST
                | rustacuda::context::ContextFlags::SCHED_AUTO,
            device,
        )?;
        rustacuda::context::ContextStack::pop()?;

        let memory = device.total_memory()?;
        let compute_units =
            device.get_attribute(rustacuda::device::DeviceAttribute::MultiprocessorCount)? as u32;
        let compute_capability = (
            device.get_attribute(rustacuda::device::DeviceAttribute::ComputeCapabilityMajor)?
                as u32,
            device.get_attribute(rustacuda::device::DeviceAttribute::ComputeCapabilityMinor)?
                as u32,
        );
        let context = owned_context.get_unowned();

        contexts.push(owned_context);

        all_devices.push(Device { memory, compute_units, compute_capability, context });
    }

    let wrapped_contexts = CudaContexts(contexts);

    Ok((all_devices, wrapped_contexts))
}

pub struct Device {
    pub memory: usize,
    pub compute_units: u32,
    pub compute_capability: (u32, u32),
    pub context: rustacuda::context::UnownedContext,
}

pub static DEVICES: Lazy<(Vec<Device>, CudaContexts)> = Lazy::new(|| {
    build_device_list().unwrap()
});
