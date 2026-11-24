#version 300 es

#ifdef GL_ES
precision highp float;
#endif

in vec2 tex;
layout(location = 0) out vec2 color;

void main()
{
	color = vec2(32768.0 / 65535.0);
}
