/*
 * Copyright 2025 Androidacy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.androidacy.apifier.progress

/**
 * One point-in-time byte count for whichever phase of a call is active, upload or download.
 *
 * A call's phases run strictly in sequence: the request body is fully sent before the response
 * arrives, so [bytesTransferred] never needs to say which phase it belongs to.
 *
 * [contentLength] is -1 when the total size is not known ahead of time, in which case no
 * emission ever carries [bytesTransferred] equal to it: there is no total to reach.
 */
data class Progress(val bytesTransferred: Long, val contentLength: Long)
