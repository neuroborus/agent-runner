// Only this checked-in entry composes native CI effects. Approved releases
// supply data and pins; they never replace factories or repository modules.
export {
  createPrerequisiteEffects,
  createNativeBuildEffects as createBuildEffects,
  createNativeSystemEffects as createSystemEffects,
} from "./index.js";
