export class ListBean {
  constructor(height?: number, tag?: number, name?: string, list?: string[]) {
    this.height = height
    this.tag = tag
    this.name = name
    this.list = list
  }

  height?: number
  tag?: number
  name?: string
  list?: string[]
}