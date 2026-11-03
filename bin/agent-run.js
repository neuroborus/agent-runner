#!/usr/bin/env node

import { startApplication } from "../src/runtime/index.js";

process.exitCode = await startApplication();
