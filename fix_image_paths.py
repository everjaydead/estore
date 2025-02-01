import sqlite3

def fix_image_paths():
    try:
        # Connect to the database
        conn = sqlite3.connect('joone.db')
        cursor = conn.cursor()

        # Update the image paths
        cursor.execute("""
            UPDATE products 
            SET image = REPLACE(image, 'static/', '')
            WHERE image LIKE 'static/%'
        """)

        # Commit the changes
        conn.commit()

        # Print the updated records to verify
        cursor.execute("SELECT id, name, image FROM products")
        products = cursor.fetchall()
        print("\nUpdated product images:")
        for product in products:
            print(f"ID: {product[0]}, Name: {product[1]}, Image: {product[2]}")

        print("\nDatabase updated successfully!")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    
    finally:
        conn.close()

if __name__ == "__main__":
    fix_image_paths()